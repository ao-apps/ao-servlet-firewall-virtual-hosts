/*
 * ao-servlet-firewall-virtual-hosts - Virtual host support for servlet-based application request filtering.
 * Copyright (C) 2018  AO Industries, Inc.
 *     support@aoindustries.com
 *     7262 Bull Pen Cir
 *     Mobile, AL 36695
 *
 * This file is part of ao-servlet-firewall-virtual-hosts.
 *
 * ao-servlet-firewall-virtual-hosts is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ao-servlet-firewall-virtual-hosts is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with ao-servlet-firewall-virtual-hosts.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.aoindustries.servlet.firewall.virtualhosts;

import com.aoindustries.net.DomainName;
import com.aoindustries.net.HostAddress;
import com.aoindustries.net.InetAddress;
import com.aoindustries.net.Path;
import com.aoindustries.net.Port;
import com.aoindustries.net.Protocol;
import com.aoindustries.servlet.firewall.api.Rule;
import com.aoindustries.validation.ValidationException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.tuple.ImmutablePair;

/**
 * Manages the mapping of incoming requests to {@link VirtualHost virtual host} and
 * the per-virtual-host virtual {@link Path path}.
 * <p>
 * Each virtual host is identified by a canonical {@link DomainName domain}.  However,
 * any number of {@link HostAddress hostnames} may be routed to the virtual host.
 * The hostnames do not necessarily have to include the domain, such as in development
 * modes, but this will often be the case.
 * </p>
 * <p>
 * Multiple "environments" are supported, each of which is a different mapping of
 * requests to virtual hosts.  Links between hosts must consider the environment when
 * choosing how to generate links to other virtual hosts.
 * </p>
 * <p>
 * Environments are matched in the order registered.  This may be significant when there
 * are ambiguities in the mapping.
 * </p>
 * <p>
 * An example of a production environment might be:
 * </p>
 * <ol>
 * <li>aoindustries.com:/ -&gt; domain=aoindustries.com, base=/</li>
 * <li>www.aoindustries.com:/ -&gt; domain=aoindustries.com, base=/</li>
 * <li>semanticcms.com:/ -&gt; domain=semanticcms.com, base=/</li>
 * <li>www.semanticcms.com:/ -&gt; domain=semanticcms.com, base=/</li>
 * <li>pragmatickm.com:/ -&gt; domain=pragmatickm.com, base=/</li>
 * <li>www.pragmatickm.com:/ -&gt; domain=pragmatickm.com, base=/</li>
 * <li>aorepo.org:/ -&gt; domain=aorepo.org, base=/</li>
 * <li>www.aorepo.org:/ -&gt; domain=aorepo.org, base=/</li>
 * </ol>
 * <p>
 * The corresponding development environment would be:
 * </p>
 * <ol>
 * <li>localhost:/aoindustries.com/ -&gt; domain=aoindustries.com, base=/</li>
 * <li>localhost:/semanticcms.com/ -&gt; domain=semanticcms.com, base=/</li>
 * <li>localhost:/pragmatickm.com/ -&gt; domain=pragmatickm.com, base=/</li>
 * <li>localhost:/aorepo.org/ -&gt; domain=aorepo.org, base=/</li>
 * </ol>
 * <p>
 * The resulting per-virtual-host paths are in a virtual space introduced by
 * this API and not directly part of the standard Servlet API.  How they are
 * handled and mapped onto servlet container resources is up the application and
 * not defined here.
 * </p>
 * <p>
 * It is possible, but not required, to configure a default host.  When a default
 * host is set, any request not matching the mappings will be assigned to this host.
 * When there is no default host set, non-matching requests are never passed through
 * virtual hosting lists of rules.
 * </p>
 * <p>
 * Among all the hostnames mapped to a virtual host, one may be specified as "canonical".
 * By default, the first non-IP-address hostname is considered the canonical.
 * </p>
 * <p>
 * Per-virtual host, with a global default if unspecified per host, it is possible
 * to canonicalize the host, which means 301 redirect requests to alternate hostnames
 * to the primary.  Requests to IP addresses will not be redirected.  Also, only
 * OPTIONS, GET, and HEAD requests are redirected.  This allows a POST to not lose its
 * content due to a redirect.  When using 303 redirect after POST, this would then get
 * redirected to the canonical hostname.  TODO: 307 redirect for non-OPTIONS/HEAD/GET.
 * </p>
 * <p>
 * Virtual host rules are invoked before non-virtual-host rules.  If the virtual
 * rule rules result in a terminal action, the non-virtual-host rules are never
 * performed.
 * </p>
 */
public class VirtualHostManager {

	// <editor-fold defaultstate="collapsed" desc="Instance Management">
	private static final String APPLICATION_ATTRIBUTE_NAME = VirtualHostManager.class.getName();

	private static class InstanceLock extends Object {}
	private static final InstanceLock instanceLock = new InstanceLock();

	/**
	 * Gets the {@link VirtualHostManager} for the given {@link ServletContext},
	 * creating a new instance if not yet present.
	 */
	public static VirtualHostManager getVirtualHostManager(ServletContext servletContext) {
		synchronized(instanceLock) {
			VirtualHostManager instance = (VirtualHostManager)servletContext.getAttribute(APPLICATION_ATTRIBUTE_NAME);
			if(instance == null) {
				instance = new VirtualHostManager();
				servletContext.setAttribute(APPLICATION_ATTRIBUTE_NAME, instance);
				// TODO: How do we register this with global rules?
			}
			return instance;
		}
	}
	// </editor-fold>

	// Locks shared from Environment to avoid possible deadlock
	private final ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock();
	final Lock readLock = rwLock.readLock();
	final Lock writeLock = rwLock.writeLock();

	private VirtualHostManager() {}

	// <editor-fold defaultstate="collapsed" desc="Virtual Hosts">
	private final Map<DomainName,VirtualHost> virtualHosts = new LinkedHashMap<DomainName,VirtualHost>();

	/**
	 * Creates a new virtual host.
	 *
	 * @param  canonicalBase  When {@code null}, a canonical base will be generated via {@link VirtualHost#generateCanonicalBase(com.aoindustries.net.DomainName)}.
	 *
	 * @throws  IllegalStateException  If a virtual host already exists on the {@link VirtualHost#getDomain() host's domain}.
	 */
	public VirtualHost newVirtualHost(DomainName domain, URLBase canonicalBase, Iterable<? extends Rule> rules) throws IllegalStateException {
		writeLock.lock();
		try {
			if(virtualHosts.containsKey(domain)) throw new IllegalStateException("Virtual host with the domain already exists: " + domain);
			VirtualHost vhost = new VirtualHost(domain, canonicalBase);
			vhost.append(rules);
			if(virtualHosts.put(domain, vhost) != null) throw new AssertionError();
			return vhost;
		} finally {
			writeLock.unlock();
		}
	}

	/**
	 * Creates a new virtual host.
	 *
	 * @param  canonicalBase  When {@code null}, a canonical base will be generated via {@link VirtualHost#generateCanonicalBase(com.aoindustries.net.DomainName)}.
	 *
	 * @throws  IllegalStateException  If a virtual host already exists on the {@link VirtualHost#getDomain() host's domain}.
	 */
	public VirtualHost newVirtualHost(DomainName domain, URLBase canonicalBase, Rule ... rules) throws IllegalStateException {
		return newVirtualHost(domain, canonicalBase, Arrays.asList(rules));
	}

	/**
	 * Creates a new virtual host.
	 * Generates a default canonical base as <code>https://${domain}</code>.
	 *
	 * @see  VirtualHost#generateCanonicalBase(com.aoindustries.net.DomainName)
	 *
	 * @throws  IllegalStateException  If a virtual host already exists on the {@link VirtualHost#getDomain() host's domain}.
	 */
	public VirtualHost newVirtualHost(DomainName domain, Iterable<? extends Rule> rules) throws IllegalStateException {
		return newVirtualHost(domain, null, rules);
	}

	/**
	 * Creates a new virtual host.
	 * Generates a default canonical base as <code>https://${domain}</code>.
	 *
	 * @see  VirtualHost#generateCanonicalBase(com.aoindustries.net.DomainName)
	 *
	 * @throws  IllegalStateException  If a virtual host already exists on the {@link VirtualHost#getDomain() host's domain}.
	 */
	public VirtualHost newVirtualHost(DomainName domain, Rule ... rules) throws IllegalStateException {
		return newVirtualHost(domain, null, Arrays.asList(rules));
	}

	// TODO: remove?

	/**
	 * Finds the virtual host registered at the given domain.
	 *
	 * @see  #newVirtualHost(com.aoindustries.net.DomainName, com.aoindustries.servlet.firewall.virtualhosts.URLBase, java.lang.Iterable)
	 * @see  #newVirtualHost(com.aoindustries.net.DomainName, com.aoindustries.servlet.firewall.virtualhosts.URLBase, com.aoindustries.servlet.firewall.api.Rule...)
	 * @see  #newVirtualHost(com.aoindustries.net.DomainName, java.lang.Iterable)
	 * @see  #newVirtualHost(com.aoindustries.net.DomainName, com.aoindustries.servlet.firewall.api.Rule...)
	 */
	public VirtualHost getVirtualHost(DomainName domain) {
		readLock.lock();
		try {
			return virtualHosts.get(domain);
		} finally {
			readLock.unlock();
		}
	}
	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="Environments">
	/**
	 * Contains all environments, in the order created.
	 */
	private final Map<String,Environment> environmentsByName = new LinkedHashMap<String,Environment>();

	/**
	 * Creates a new, empty environment.
	 *
	 * @throws  IllegalStateException  If an environment already exists with this name.
	 */
	public Environment newEnvironment(String name) throws IllegalStateException {
		writeLock.lock();
		try {
			if(environmentsByName.containsKey(name)) {
				throw new IllegalStateException("Environment already exists with name: " + name);
			}
			Environment environment = new Environment(this, name);
			environmentsByName.put(name, environment);
			return environment;
		} finally {
			writeLock.unlock();
		}
	}
	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="Request Matching">
	/**
	 * Contains the first environment added for each unique base.  It is possible for multiple environments to have
	 * the same {@link URLBase}, but only the first one is kept here.  This is the order requests
	 * are searched in {@link #search(javax.servlet.http.HttpServletRequest)}.
	 */
	private final Map<URLBase,ImmutablePair<Environment,DomainName>> searchOrder = new LinkedHashMap<URLBase,ImmutablePair<Environment,DomainName>>();

	/**
	 * Adds a new item to the search order, if the base has not already been used.
	 *
	 * @see  Environment#add(java.util.Map)
	 */
	void addSearchOrder(URLBase base, Environment environment, DomainName domain) {
		assert rwLock.isWriteLockedByCurrentThread();
		if(
			// Keep first occurrence per base
			!searchOrder.containsKey(base)
			&& searchOrder.put(
				base,
				ImmutablePair.of(environment, domain)
			) != null
		) throw new AssertionError();
	}

	private static HostAddress getRequestHost(ServletRequest request) throws ValidationException {
		String serverName = request.getServerName();
		int serverNameLen = serverName.length();
		if(
			serverNameLen >= 2
			&& serverName.charAt(0) == '['
			&& serverName.charAt(serverNameLen - 1) == ']'
		) {
			// Parse as IPv6 address
			return HostAddress.valueOf(
				InetAddress.valueOf(serverName.substring(1, serverNameLen - 1))
			);
		} else {
			// Use default parsing
			return HostAddress.valueOf(serverName);
		}
	}

	private static Port getRequestPort(ServletRequest request) throws ValidationException {
		return Port.valueOf(
			request.getServerPort(),
			Protocol.TCP // Assuming TCP here
		);
	}

	/**
	 * Matches the given request to an {@link Environment environment} and
	 * {@link VirtualHost virtual host}.
	 * <p>
	 * Search the environments in the order added.
	 * Within each environment, searches the {@link URLBase bases}
	 * in the order added.
	 * </p>
	 *
	 * @return  The match or {@code null} if no match found.
	 *
	 * @throws ServletException when a request value is incompatible with the self-validating types
	 */
	public VirtualHostMatch search(HttpServletRequest request) throws ServletException {
		try {
			readLock.lock();
			try {
				// Fields obtained from request as-needed
				String requestScheme = null;
				HostAddress requestHost = null;
				Port requestPort = null;
				String requestContextPath = null;
				String requestPath = null;
				for(Map.Entry<URLBase,ImmutablePair<Environment,DomainName>> entry : searchOrder.entrySet()) {
					URLBase base = entry.getKey();
					String scheme = base.getScheme();
					if(scheme != null) {
						if(requestScheme == null) requestScheme = request.getScheme();
						if(!scheme.equalsIgnoreCase(requestScheme)) continue;
					}
					HostAddress host = base.getHost();
					if(host != null) {
						if(requestHost == null) requestHost = getRequestHost(request);
						if(!host.equals(requestHost)) continue;
					}
					Port port = base.getPort();
					if(port != null) {
						if(requestPort == null) getRequestPort(request);
						if(!port.equals(requestPort)) continue;
					}
					Path contextPath = base.getContextPath();
					if(contextPath != null) {
						if(requestContextPath == null) requestContextPath = request.getContextPath();
						if(contextPath == Path.ROOT) {
							if(!requestContextPath.isEmpty()) continue;
						} else {
							if(!contextPath.toString().equals(requestContextPath)) continue;
						}
					}
					Path prefix = base.getPrefix();
					if(prefix != null) {
						if(requestPath == null) {
							requestPath = request.getServletPath();
							String pathInfo = request.getPathInfo();
							if(pathInfo != null) requestPath += pathInfo;
						}
						if(!requestPath.startsWith(prefix.toString())) continue;
					}
					URLBase completeBase;
					if(base.isComplete()) {
						completeBase = base;
					} else {
						String completeScheme;
						if(scheme == null) {
							if(requestScheme == null) requestScheme = request.getScheme();
							completeScheme = requestScheme;
						} else {
							completeScheme = scheme;
						}
						HostAddress completeHost;
						if(host == null) {
							if(requestHost == null) requestHost = getRequestHost(request);
							completeHost = requestHost;
						} else {
							completeHost = host;
						}
						Port completePort;
						if(port == null) {
							if(requestPort == null) requestPort = getRequestPort(request);
							completePort = requestPort;
						} else {
							completePort = port;
						}
						Path completeContextPath;
						if(contextPath == null) {
							if(requestContextPath == null) requestContextPath = request.getContextPath();
							completeContextPath = requestContextPath.isEmpty() ? Path.ROOT : Path.valueOf(requestContextPath);
						} else {
							completeContextPath = contextPath;
						}
						completeBase = URLBase.valueOf(
							completeScheme,
							completeHost,
							completePort,
							completeContextPath,
							prefix
						);
					}
					if(requestPath == null) {
						requestPath = request.getServletPath();
						String pathInfo = request.getPathInfo();
						if(pathInfo != null) requestPath += pathInfo;
					}
					ImmutablePair<Environment,DomainName> pair = entry.getValue();
					DomainName domain = pair.getRight();
					return new VirtualHostMatch(
						pair.getLeft(),
						base,
						completeBase,
						virtualHosts.get(domain),
						new VirtualPath(
							domain,
							Path.valueOf(prefix == null ? requestPath : requestPath.substring(prefix.toString().length() - 1))
						)
					);
				}
				return null;
			} finally {
				readLock.unlock();
			}
		} catch(ValidationException e) {
			throw new ServletException(e);
		}
	}
	// </editor-fold>
}

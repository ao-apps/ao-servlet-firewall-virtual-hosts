/*
 * ao-servlet-firewall-virtual-hosts - Virtual host support for servlet-based application request filtering.
 * Copyright (C) 2018, 2019, 2020, 2021, 2022  AO Industries, Inc.
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
 * along with ao-servlet-firewall-virtual-hosts.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.aoapps.servlet.firewall.virtualhosts;

import com.aoapps.net.DomainName;
import com.aoapps.net.HostAddress;
import com.aoapps.net.Path;
import com.aoapps.net.partialurl.FieldSource;
import com.aoapps.net.partialurl.PartialURL;
import com.aoapps.net.partialurl.servlet.HttpServletRequestFieldSource;
import com.aoapps.servlet.attribute.ScopeEE;
import com.aoapps.servlet.firewall.api.Rule;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebListener;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.NotImplementedException;
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
 * <li>aoindustries.com:/ -&gt; domain=aoindustries.com, prefix=/</li>
 * <li>www.aoindustries.com:/ -&gt; domain=aoindustries.com, prefix=/</li>
 * <li>semanticcms.com:/ -&gt; domain=semanticcms.com, prefix=/</li>
 * <li>www.semanticcms.com:/ -&gt; domain=semanticcms.com, prefix=/</li>
 * <li>pragmatickm.com:/ -&gt; domain=pragmatickm.com, prefix=/</li>
 * <li>www.pragmatickm.com:/ -&gt; domain=pragmatickm.com, prefix=/</li>
 * <li>aorepo.org:/ -&gt; domain=aorepo.org, prefix=/</li>
 * <li>www.aorepo.org:/ -&gt; domain=aorepo.org, prefix=/</li>
 * </ol>
 * <p>
 * The corresponding development environment would be:
 * </p>
 * <ol>
 * <li>localhost:/aoindustries.com/ -&gt; domain=aoindustries.com, prefix=/</li>
 * <li>localhost:/semanticcms.com/ -&gt; domain=semanticcms.com, prefix=/</li>
 * <li>localhost:/pragmatickm.com/ -&gt; domain=pragmatickm.com, prefix=/</li>
 * <li>localhost:/aorepo.org/ -&gt; domain=aorepo.org, prefix=/</li>
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
public final class VirtualHostManager {

	// <editor-fold defaultstate="collapsed" desc="Instance Management">
	@WebListener
	public static class Initializer implements ServletContextListener {
		@Override
		public void contextInitialized(ServletContextEvent event) {
			getInstance(event.getServletContext());
		}
		@Override
		public void contextDestroyed(ServletContextEvent event) {
			// Do nothing
		}
	}

	private static final ScopeEE.Application.Attribute<VirtualHostManager> APPLICATION_ATTRIBUTE =
		ScopeEE.APPLICATION.attribute(VirtualHostManager.class.getName());

	/**
	 * Gets the {@link VirtualHostManager} for the given {@link ServletContext},
	 * creating a new instance if not yet present.
	 */
	public static VirtualHostManager getInstance(ServletContext servletContext) {
		return APPLICATION_ATTRIBUTE.context(servletContext).computeIfAbsent(__ -> {
			VirtualHostManager instance = new VirtualHostManager();
			// TODO: How do we register this with global rules?
			return instance;
		});
	}
	// </editor-fold>

	// Locks shared from Environment to avoid possible deadlock
	private final ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock();
	final Lock readLock = rwLock.readLock();
	final Lock writeLock = rwLock.writeLock();

	private VirtualHostManager() {
		// Do nothing
	}

	// <editor-fold defaultstate="collapsed" desc="Virtual Hosts">
	private final Map<DomainName, VirtualHost> virtualHosts = new LinkedHashMap<>();

	/**
	 * Creates a new virtual host.
	 *
	 * @param  canonicalPartialURL  When {@code null}, a canonical partial URL will be generated via {@link VirtualHost#generateCanonicalPartialURL(com.aoapps.net.DomainName)}.
	 *
	 * @throws  IllegalStateException  If a virtual host already exists on the {@link VirtualHost#getDomain() host's domain}.
	 */
	public VirtualHost newVirtualHost(DomainName domain, PartialURL canonicalPartialURL, Iterable<? extends Rule> rules) throws IllegalStateException {
		writeLock.lock();
		try {
			if(virtualHosts.containsKey(domain)) throw new IllegalStateException("Virtual host with the domain already exists: " + domain);
			VirtualHost vhost = new VirtualHost(domain, canonicalPartialURL);
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
	 * @param  canonicalPartialURL  When {@code null}, a canonical partial URL will be generated via {@link VirtualHost#generateCanonicalPartialURL(com.aoapps.net.DomainName)}.
	 *
	 * @throws  IllegalStateException  If a virtual host already exists on the {@link VirtualHost#getDomain() host's domain}.
	 */
	public VirtualHost newVirtualHost(DomainName domain, PartialURL canonicalPartialURL, Rule ... rules) throws IllegalStateException {
		return newVirtualHost(domain, canonicalPartialURL, Arrays.asList(rules));
	}

	/**
	 * Creates a new virtual host.
	 * Generates a default canonical partial URL as <code>https://${domain}</code>.
	 *
	 * @see  VirtualHost#generateCanonicalPartialURL(com.aoapps.net.DomainName)
	 *
	 * @throws  IllegalStateException  If a virtual host already exists on the {@link VirtualHost#getDomain() host's domain}.
	 */
	public VirtualHost newVirtualHost(DomainName domain, Iterable<? extends Rule> rules) throws IllegalStateException {
		return newVirtualHost(domain, null, rules);
	}

	/**
	 * Creates a new virtual host.
	 * Generates a default canonical partial URL as <code>https://${domain}</code>.
	 *
	 * @see  VirtualHost#generateCanonicalPartialURL(com.aoapps.net.DomainName)
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
	 * @see  #newVirtualHost(com.aoapps.net.DomainName, com.aoapps.net.partialurl.PartialURL, java.lang.Iterable)
	 * @see  #newVirtualHost(com.aoapps.net.DomainName, com.aoapps.net.partialurl.PartialURL, com.aoapps.servlet.firewall.api.Rule...)
	 * @see  #newVirtualHost(com.aoapps.net.DomainName, java.lang.Iterable)
	 * @see  #newVirtualHost(com.aoapps.net.DomainName, com.aoapps.servlet.firewall.api.Rule...)
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
	private final Map<String, Environment> environmentsByName = new LinkedHashMap<>();

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
	 * Contains the first environment added for each unique partial URL.  It is possible for multiple environments to have
	 * the same {@link PartialURL}, but only the first one is kept here.  This is the order requests
	 * are searched in {@link #search(javax.servlet.http.HttpServletRequest)}.
	 */
	private final Map<PartialURL, ImmutablePair<Environment, DomainName>> searchOrder = new LinkedHashMap<>();

	/**
	 * Adds a new item to the search order, if the partial URL has not already been used.
	 *
	 * @see  Environment#add(java.util.Map)
	 */
	void addSearchOrder(PartialURL partialURL, Environment environment, DomainName domain) {
		assert rwLock.isWriteLockedByCurrentThread();
		if(
			// Keep first occurrence per partial URL
			!searchOrder.containsKey(partialURL)
			&& searchOrder.put(
				partialURL,
				ImmutablePair.of(environment, domain)
			) != null
		) throw new AssertionError();
	}

	/**
	 * Matches the given request to an {@link Environment environment} and
	 * {@link VirtualHost virtual host} via {@link HttpServletRequestFieldSource}.
	 * <p>
	 * Search the environments in the order added.
	 * Within each environment, searches the {@link PartialURL partial URLs}
	 * in the order added.
	 * </p>
	 *
	 * @return  The match or {@code null} if no match found.
	 *
	 * @throws ServletException when a request value is incompatible with the self-validating types
	 */
	public VirtualHostMatch search(HttpServletRequest request) throws IOException, ServletException {
		FieldSource fieldSource = new HttpServletRequestFieldSource(request);
		readLock.lock();
		try {
			throw new NotImplementedException("TODO: Finish implementation");
			/* TODO: Finish implementation
			// Fields obtained from request as-needed
			for(Map.Entry<PartialURL, ImmutablePair<Environment, DomainName>> entry : searchOrder.entrySet()) {
				// TODO: Use indexed map lookup
				PartialURL partialURL = entry.getKey();
				String scheme = partialURL.getScheme();
				if(scheme != null && !scheme.equalsIgnoreCase(fieldSource.getScheme())) continue;
				HostAddress host = partialURL.getHost();
				if(host != null && !host.equals(fieldSource.getHost())) continue;
				Port port = partialURL.getPort();
				if(port != null && !port.equals(fieldSource.getPort())) continue;
				Path contextPath = partialURL.getContextPath();
				if(contextPath != null && !contextPath.equals(fieldSource.getContextPath())) continue;
				Path prefix = partialURL.getPrefix();
				if(prefix != null && !fieldSource.getPath().toString().startsWith(prefix.toString())) continue;
				ImmutablePair<Environment, DomainName> pair = entry.getValue();
				DomainName domain = pair.getRight();
				return new VirtualHostMatch(
					pair.getLeft(),
					partialURL,
					// TODO: A SinglePartialURL that has fields matching a multi, selected from this request?
					//       This could be useful for maintaining the current values when generating URLs.
					partialURL.toURL(fieldSource), // toURL should use matching values from request when is a MultiPartialURL
					virtualHosts.get(domain),
					new VirtualPath(
						domain,
						prefix == null ? fieldSource.getPath() : fieldSource.getPath().suffix(prefix.toString().length() - 1)
					)
				);
			}
			return null;
			 */
		} finally {
			readLock.unlock();
		}
	}
	// </editor-fold>
}

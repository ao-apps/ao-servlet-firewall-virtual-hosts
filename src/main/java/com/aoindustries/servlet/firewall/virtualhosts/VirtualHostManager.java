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
import com.aoindustries.net.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import javax.servlet.ServletContext;

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

	private final Lock readLock;
	private final Lock writeLock;
	{
		ReadWriteLock rwLock = new ReentrantReadWriteLock();
		readLock = rwLock.readLock();
		writeLock = rwLock.writeLock();
	}

	private final Map<DomainName,VirtualHost> virtualHosts = new LinkedHashMap<DomainName,VirtualHost>();

	private final Map<HostAddress,Map<Path,VirtualHost>> mappings = new LinkedHashMap<HostAddress,Map<Path,VirtualHost>>();

	private VirtualHostManager() {}

	/**
	 * Registers a new virtual host.
	 *
	 * @throws  IllegalArgumentException  If a virtual host already exists on the {@link VirtualHost#getDomain() host's domain}.
	 */
	public VirtualHostManager add(VirtualHost vhost) throws IllegalArgumentException {
		writeLock.lock();
		try {
			DomainName domain = vhost.getDomain();
			if(virtualHosts.containsKey(domain)) throw new IllegalArgumentException("Virtual host with the domain already exists: " + domain);
			if(virtualHosts.put(domain, vhost) != null) throw new AssertionError();
		} finally {
			writeLock.unlock();
		}
		return this;
	}

	/**
	 * Registers any number of new virtual hosts.
	 *
	 * @throws  IllegalArgumentException  If a virtual host already exists on the {@link VirtualHost#getDomain() host's domain}.
	 */
	// TODO: Rename "register" or "allocate" to be more clear this is reserving a space?
	public VirtualHostManager add(VirtualHost ... vhosts) throws IllegalArgumentException {
		writeLock.lock();
		try {
			for(VirtualHost vhost : vhosts) add(vhost);
		} finally {
			writeLock.unlock();
		}
		return this;
	}

	// TODO: add overloads matching the static factory methods of VirtualHost?
	//       Move those factory methods here instead, so there cannot be VirtualHost in unregistered form?
	//       Remove varargs method and use method chaining if we go this route.

	// TODO: remove?

	/**
	 * Finds the virtual host registered at the given domain.
	 */
	public VirtualHost get(DomainName domain) {
		readLock.lock();
		try {
			return virtualHosts.get(domain);
		} finally {
			readLock.unlock();
		}
	}

	// TODO: Environments, with environment attributes
}

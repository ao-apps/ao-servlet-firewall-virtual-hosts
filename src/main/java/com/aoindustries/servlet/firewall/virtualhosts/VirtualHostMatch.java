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

import com.aoindustries.net.partialurl.PartialURL;
import com.aoindustries.net.partialurl.servlet.HttpServletRequestFieldSource;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;

/**
 * The result of a call to {@link VirtualHostManager#search(javax.servlet.http.HttpServletRequest)}.
 */
public class VirtualHostMatch {

	private final Environment environment;
	private final PartialURL partialURL;
	private final URL url;
	private final VirtualHost virtualHost;
	private final VirtualPath virtualPath;

	VirtualHostMatch(
		Environment environment,
		PartialURL partialURL,
		URL url,
		VirtualHost virtualHost,
		VirtualPath virtualPath
	) {
		this.environment = environment;
		this.partialURL = partialURL;
		this.url = url;
		assert virtualHost != null;
		this.virtualHost = virtualHost;
		assert virtualPath.getDomain().equals(virtualHost.getDomain());
		this.virtualPath = virtualPath;
	}

	@Override
	public String toString() {
		return partialURL + " -> " + url + " -> " + virtualPath;
	}

	public Environment getEnvironment() {
		return environment;
	}

	/**
	 * Gets the partial URL that matched.  This may contain null fields and is not necessarily
	 * {@link PartialURL#isComplete() complete}.
	 */
	public PartialURL getPartialURL() {
		return partialURL;
	}

	/**
	 * Gets the {@link PartialURL#toURL(com.aoindustries.net.partialurl.FieldSource) completed URL} that matched, with any
	 * {@code null} fields provided from the {@link HttpServletRequest request} via {@link HttpServletRequestFieldSource}.
	 */
	public URL getUrl() {
		return url;
	}

	/**
	 * Gets the {@link VirtualHost virtual host} that matched the request.
	 */
	public VirtualHost getVirtualHost() {
		return virtualHost;
	}

	/**
	 * Gets the {@link VirtualPath virtual path} within the virtual host that matched, which
	 * is the part of the request path (servletPath + pathInfo) past the prefix (and including
	 * the prefix's trailing slash).
	 * <p>
	 * This will always have a {@link VirtualPath#getDomain() domain} matching
	 * the {@link VirtualHost#getDomain() domain of the virtual host}.
	 * </p>
	 */
	public VirtualPath getVirtualPath() {
		return virtualPath;
	}
}

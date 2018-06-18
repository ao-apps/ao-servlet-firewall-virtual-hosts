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

import com.aoindustries.net.HostAddress;
import com.aoindustries.net.Path;
import com.aoindustries.net.Port;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Locale;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.ObjectUtils;

/**
 * A {@link URLBase} contains a scheme, host, port, contextPath, and prefix.
 * All fields are optional.
 * <p>
 * This is not a general-purpose representation of a URL.  It only contains the
 * fields specifically used for matching a request to a virtual host.  For
 * an instance of {@link URL}, see {@link 
 * </p>
 * <p>
 * A {@link URLBase} consisting of all null fields will match
 * all requests and can serve as a match for a default host.
 * </p>
 */
public class URLBase implements Comparable<URLBase> {

	/**
	 * The http scheme.
	 */
	public static final String HTTP = "http";

	/**
	 * The https scheme.
	 */
	public static final String HTTPS = "https";

	/**
	 * The character used to represent request-value substitutions.
	 *
	 * @see  #WILDCARD_STRING
	 */
	private static final char WILDCARD_CHAR = '*';

	/**
	 * The character used to represent request-value substitutions.
	 *
	 * @see  #WILDCARD_CHAR
	 */
	private static final String WILDCARD_STRING = String.valueOf(WILDCARD_CHAR);

	/**
	 * The value used to represent {@code null} {@link #contextPath}.
	 */
	private static final String NULL_CONTEXT_PATH = Path.SEPARATOR_STRING + WILDCARD_CHAR;

	/**
	 * The value used to represent {@code null} {@link #prefix}.
	 */
	private static final String NULL_PREFIX = Path.SEPARATOR_STRING + WILDCARD_CHAR + WILDCARD_CHAR;

	/**
	 * A base that matches all requests, useful for default hosts.
	 */
	public static final URLBase DEFAULT = new URLBase(null, null, null, null, null);

	/**
	 * Gets a base URL supporting {@link ServletRequest requests} across multiple schemes/hosts/ports/...
	 * 
	 * @param scheme       (Optional) The scheme (http/https/...) to match and/or link to
	 * @param host         (Optional) The IP/host to match and/or link to
	 * @param port         (Optional) The port to match and/or link to
	 * @param contextPath  (Optional) The contextPath to match and/or link to
	 * @param prefix       (Optional) The prefix to match against the path or {@code null} to match all.
	 *                                Must be either {@code null} or always ends in a slash (/).
	 *
	 * @see  #valueOf(com.aoindustries.net.Path)
	 * @see  #URLBase(java.lang.String, com.aoindustries.net.HostAddress, com.aoindustries.net.Port, com.aoindustries.net.Path, com.aoindustries.net.Path)
	 */
	public static URLBase valueOf(String scheme, HostAddress host, Port port, Path contextPath, Path prefix) {
		if(
			scheme == null
			&& host == null
			&& port == null
			&& contextPath == null
			&& prefix == null
		) {
			return DEFAULT;
		} else {
			return new URLBase(scheme, host, port, contextPath, prefix);
		}
	}

	/**
	 * Gets a base URL always within the current {@link ServletRequest request}.
	 *
	 * @param prefix       (Optional) The prefix to match against the path or {@code null} to match all.
	 *                                Must be either {@code null} or always ends in a slash (/).
	 *
	 * @see  #valueOf(java.lang.String, com.aoindustries.net.HostAddress, com.aoindustries.net.Port, com.aoindustries.net.Path, com.aoindustries.net.Path)
	 */
	public static URLBase valueOf(Path prefix) {
		return valueOf(null, null, null, null, prefix);
	}

	private final String scheme;
	private final String schemeLower;
	private final HostAddress host;
	private final Port port;
	private final Path contextPath;
	private final Path prefix;

	/**
	 * @see  #valueOf(java.lang.String, com.aoindustries.net.HostAddress, com.aoindustries.net.Port, com.aoindustries.net.Path, com.aoindustries.net.Path)
	 */
	private URLBase(String scheme, HostAddress host, Port port, Path contextPath, Path prefix) {
		this.scheme = scheme;
		this.schemeLower = (scheme == null) ? null : scheme.toLowerCase(Locale.ROOT);
		this.host = host;
		this.port = port;
		if(contextPath != null && contextPath != Path.ROOT) {
			String contextPathStr = contextPath.toString();
			if(contextPathStr.endsWith(Path.SEPARATOR_STRING)) {
				throw new IllegalArgumentException("Non-root context path may not end in slash (" + Path.SEPARATOR_CHAR + "): " + contextPath);
			}
		}
		this.contextPath = contextPath;
		if(prefix != null && !prefix.toString().endsWith(Path.SEPARATOR_STRING)) {
			throw new IllegalArgumentException("Prefix does not end in slash (" + Path.SEPARATOR_CHAR + "): " + prefix);
		}
		this.prefix = prefix;
	}

	@Override
	public String toString() {
		String hostStr = (host == null ? WILDCARD_STRING : host.toBracketedString());
		int toStringLen =
			(scheme == null) ? 0 : (
				scheme.length()
				+ 1 // ':'
			)
			+ 2 // "//"
			+ hostStr.length();
		String portStr;
		if(port == null) {
			portStr = WILDCARD_STRING;
		} else {
			int portNum = port.getPort();
			if(
				(HTTP.equals(schemeLower) && portNum == 80)
				|| (HTTPS.equals(schemeLower) && portNum == 443)
			) {
				portStr = null;
			} else {
				portStr = Integer.toString(portNum);
			}
		}
		if(portStr != null) {
			toStringLen +=
				1 // ':'
				+ portStr.length();
		}
		String contextPathStr;
		if(contextPath != null) {
			contextPathStr = (contextPath == Path.ROOT) ? "" : contextPath.toString();
		} else {
			contextPathStr = NULL_CONTEXT_PATH;
		}
		toStringLen += contextPathStr.length();
		String prefixStr = (prefix == null) ? NULL_PREFIX : prefix.toString();
		toStringLen += prefixStr.length();
		StringBuilder toString = new StringBuilder(toStringLen);
		if(scheme != null) {
			toString.append(scheme).append(':');
		}
		toString.append("//").append(hostStr);
		if(portStr != null) {
			toString.append(':').append(portStr);
		}
		toString.append(contextPathStr).append(prefixStr);
		assert toStringLen == toString.length();
		return toString.toString();
	}

	@Override
	@SuppressWarnings("deprecation") // TODO: Java 1.7: No longer suppress
	public boolean equals(Object obj) {
		if(!(obj instanceof URLBase)) return false;
		URLBase other = (URLBase)obj;
		return
			ObjectUtils.equals(schemeLower, other.schemeLower)
			&& ObjectUtils.equals(host, other.host)
			&& ObjectUtils.equals(port, other.port)
			&& ObjectUtils.equals(contextPath, other.contextPath)
			&& ObjectUtils.equals(prefix, other.prefix);
	}

	@Override
	@SuppressWarnings("deprecation") // TODO: Java 1.7: No longer suppress
	public int hashCode() {
		return ObjectUtils.hashCodeMulti(
			schemeLower,
			host,
			port,
			contextPath,
			prefix
		);
	}

	@Override
	public int compareTo(URLBase other) {
		int diff = ObjectUtils.compare(host, other.host);
		if(diff != 0) return diff;
		diff = ObjectUtils.compare(contextPath, other.contextPath);
		if(diff != 0) return diff;
		diff = ObjectUtils.compare(prefix, other.prefix);
		if(diff != 0) return diff;
		diff = ObjectUtils.compare(port, other.port);
		if(diff != 0) return diff;
		return ObjectUtils.compare(scheme, other.scheme);
	}

	/**
	 * Checks if this base is complete (has no {@code null} fields other than prefix).
	 * A complete base may be converted to a {@link URL} without any
	 * {@link HttpServletRequest request} provided.
	 *
	 * @see  #toURL(javax.servlet.http.HttpServletRequest)
	 */
	public boolean isComplete() {
		return
			scheme != null
			&& host != null
			&& port != null
			&& contextPath != null;
	}

	/**
	 * Gets the general-purpose representation of {@link URL} for this base.
	 *
	 * @param  request   Only used when at least one field is {@code null} and uses the value
	 *                   from the request.  May be {@code null} when this {@link URLBase} is known
	 *                   to have all fields specified.
	 *
	 * @throws NullPointerException when {@code request} not provided and at least one field is {@code null}.
	 *
	 * @see  #isComplete()
	 */
	public URL toURL(HttpServletRequest request) {
		String schemeStr = (scheme == null) ? request.getScheme() : scheme;
		int portNum = (port == null) ? request.getServerPort() : port.getPort();
		if(
			(HTTP.equalsIgnoreCase(schemeStr) && portNum == 80)
			|| (HTTPS.equalsIgnoreCase(schemeStr) && portNum == 443)
		) {
			portNum = -1;
		}
		String hostStr = (host == null) ? request.getServerName() : host.toBracketedString();
		String file;
		if(contextPath == null) {
			String contextPathStr = request.getContextPath();
			if(contextPathStr.isEmpty()) {
				file = (prefix == null) ? "" : prefix.toString();
			} else {
				if(prefix == null) {
					file = contextPathStr;
				} else {
					file = contextPathStr + prefix.toString();
				}
			}
		} else if(contextPath == Path.ROOT) {
			file = (prefix == null) ? "" : prefix.toString();
		} else {
			if(prefix == null) {
				file = contextPath.toString();
			} else {
				file = contextPath.toString() + prefix.toString();
			}
		}
		try {
			return new URL(
				schemeStr,
				hostStr,
				portNum,
				file
			);
		} catch(MalformedURLException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Gets the scheme (http/https/possibly others) for this base URL.
	 *
	 * @return  The scheme or {@code null} when the {@link ServletRequest#getScheme() scheme of the request} should be used.
	 *
	 * @see  #HTTP
	 * @see  #HTTPS
	 * @see  ServletRequest#getScheme()
	 * @see  URL#getProtocol()
	 */
	public String getScheme() {
		return scheme;
	}

	/**
	 * Gets the IP address or hostname for this base URL.
	 *
	 * @return  The IP address/hostname or {@code null} when the {@link ServletRequest#getServerName() host of the request} should be used.
	 *
	 * @see  ServletRequest#getServerName()
	 * @see  URL#getHost()
	 */
	public HostAddress getHost() {
		return host;
	}

	/**
	 * Gets the port number for this base URL.
	 *
	 * @return  The port or {@code null} when the {@link ServletRequest#getServerPort() port of the request} should be used.
	 *
	 * @see  ServletRequest#getServerPort()
	 * @see  URL#getPort()
	 */
	public Port getPort() {
		return port;
	}

	/**
	 * Gets the context path for this base URL, only ending in a slash (/) when is
	 * {@link Path#ROOT the root context}.
	 *
	 * @return  The context path or {@code null} when the {@link HttpServletRequest#getContextPath() context path of the request} should be used.
	 *
	 * @see  HttpServletRequest#getContextPath()
	 */
	public Path getContextPath() {
		return contextPath;
	}

	/**
	 * Gets the prefix of the path for this base URL, always either {@code null} or ending in a slash (/).
	 *
	 * @see  HttpServletRequest#getServletPath()
	 * @see  HttpServletRequest#getPathInfo()
	 * @see  URL#getFile()
	 * @see  Path#SEPARATOR_CHAR
	 */
	public Path getPrefix() {
		return prefix;
	}
}

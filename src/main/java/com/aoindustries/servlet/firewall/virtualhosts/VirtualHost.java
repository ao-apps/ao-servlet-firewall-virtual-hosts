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

import com.aoindustries.lang.NullArgumentException;
import com.aoindustries.net.DomainName;
import com.aoindustries.net.HostAddress;
import com.aoindustries.net.Path;
import com.aoindustries.net.Port;
import com.aoindustries.net.Protocol;
import com.aoindustries.servlet.firewall.api.Rule;
import com.aoindustries.util.AoCollections;
import com.aoindustries.validation.ValidationException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.servlet.ServletRequest;

/**
 * A {@link VirtualHost} is matched from one or more {@link URLBase} and contains a list of per-virtual-host
 * {@link Rule rules}.  These rules are called after global rules for requests that
 * match the domains.
 */
// TODO: Per-virtual-host attributes?
public class VirtualHost {

	private static final Port HTTPS_PORT;
	static {
		try {
			HTTPS_PORT = Port.valueOf(443, Protocol.TCP);
		} catch(ValidationException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Generates the default URL base for the given domain as <code>https://${domain}/</code>.
	 */
	public static URLBase generateCanonicalBase(DomainName domain) {
		return new URLBase(
			URLBase.HTTPS,
			HostAddress.valueOf(domain),
			HTTPS_PORT,
			Path.ROOT,
			Path.ROOT
		);
	}

	private final DomainName domain;
	private final URLBase canonicalBase;

	private final List<Rule> rules = new CopyOnWriteArrayList<Rule>();

	VirtualHost(DomainName domain, URLBase canonicalBase) {
		this.domain = NullArgumentException.checkNotNull(domain, "domain");
		this.canonicalBase = (canonicalBase == null) ? generateCanonicalBase(domain) : canonicalBase;
	}

	/**
	 * Gets the unique domain name of this host.
	 * A virtual host may have any number of hostnames associated with it via
	 * {@link URLBase}, but has a single domain name.
	 * <p>
	 * It is possible for a virtual host to exist without any associated {@link URLBase}.
	 * In this case, links to it will use the canonical {@link URLBase, if present},
	 * but the host is not matched and served locally.
	 * </p>
	 */
	public DomainName getDomain() {
		return domain;
	}

	/**
	 * A virtual host always has a canonical base.  This is used to generate
	 * URLs to the virtual host when there is no matching {@link Environment environment}.
	 * <p>
	 * This canonical base may have {@code null} fields, which will be taken from
	 * the current {@link ServletRequest request}.
	 * </p>
	 */
	public URLBase getCanonicalBase() {
		return canonicalBase;
	}

	/**
	 * An unmodifiable wrapper around rules for {@link #getRules()}.
	 */
	private final List<Rule> unmodifiableRules = Collections.unmodifiableList(rules);

	/**
	 * Gets an unmodifiable copy of the rules applied to this virtual host.
	 */
	public List<Rule> getRules() {
		return unmodifiableRules;
	}

	/**
	 * A small wrapper to prevent casting back to underlying list from the object
	 * returned from {@link #getRulesIterable()}.
	 */
	private final Iterable<Rule> rulesIter = new Iterable<Rule>() {
		@Override
		public Iterator<Rule> iterator() {
			return rules.iterator();
		}
	};

	/**
	 * Gets an unmodifiable iterator to the rules.
	 *
	 * @implNote  Is unmodifiable due to being implemented as {@link CopyOnWriteArrayList#iterator()}.
	 */
	public Iterable<Rule> getRulesIterable() {
		return rulesIter;
	}

	/**
	 * Inserts rules into the beginning of this virtual host.
	 */
	public void prepend(Iterable<? extends Rule> rules) {
		this.rules.addAll(0, AoCollections.asCollection(rules));
	}

	/**
	 * Inserts rules into the beginning of this virtual host.
	 */
	public void prepend(Rule ... rules) {
		prepend(Arrays.asList(rules));
	}

	/**
	 * Inserts rules into the end of this virtual host.
	 */
	public void append(Iterable<? extends Rule> rules) {
		this.rules.addAll(AoCollections.asCollection(rules));
	}

	/**
	 * Inserts rules into the end of this virtual host.
	 */
	public void append(Rule ... rules) {
		append(Arrays.asList(rules));
	}
}

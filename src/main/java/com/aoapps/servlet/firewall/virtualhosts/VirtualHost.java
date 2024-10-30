/*
 * ao-servlet-firewall-virtual-hosts - Virtual host support for servlet-based application request filtering.
 * Copyright (C) 2018, 2019, 2020, 2021, 2022, 2024  AO Industries, Inc.
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

import com.aoapps.collections.AoCollections;
import com.aoapps.lang.NullArgumentException;
import com.aoapps.lang.validation.ValidationException;
import com.aoapps.net.DomainName;
import com.aoapps.net.HostAddress;
import com.aoapps.net.Path;
import com.aoapps.net.Port;
import com.aoapps.net.Protocol;
import com.aoapps.net.partialurl.PartialURL;
import com.aoapps.net.partialurl.SinglePartialURL;
import com.aoapps.net.partialurl.servlet.HttpServletRequestFieldSource;
import com.aoapps.servlet.firewall.api.Rule;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.servlet.http.HttpServletRequest;

/**
 * A {@link VirtualHost} is matched from one or more {@link PartialURL} and contains a list of per-virtual-host
 * {@link Rule rules}.  These rules are called after global rules for requests that
 * match the domains.
 */
// TODO: Per-virtual-host attributes?
public class VirtualHost {

  private static final Port HTTPS_PORT;

  static {
    try {
      HTTPS_PORT = Port.valueOf(443, Protocol.TCP);
    } catch (ValidationException e) {
      throw new AssertionError(e);
    }
  }

  /**
   * Generates the default partial URL for the given domain as <code>https://${domain}</code>.
   *
   * <p>TODO: Should this be a {@link URL} to not allow it to be partial?</p>
   */
  public static SinglePartialURL generateCanonicalPartialURL(DomainName domain) {
    return PartialURL.valueOf(
        PartialURL.HTTPS,
        HostAddress.valueOf(domain),
        HTTPS_PORT,
        Path.ROOT,
        null
    );
  }

  private final DomainName domain;
  private final PartialURL canonicalPartialUrl;

  private final List<Rule> rules = new CopyOnWriteArrayList<>();

  VirtualHost(DomainName domain, PartialURL canonicalPartialUrl) {
    this.domain = NullArgumentException.checkNotNull(domain, "domain");
    this.canonicalPartialUrl = (canonicalPartialUrl == null) ? generateCanonicalPartialURL(domain) : canonicalPartialUrl;
  }

  /**
   * Gets the unique domain name of this host.
   * A virtual host may have any number of hostnames associated with it via
   * {@link PartialURL}, but has a single domain name.
   *
   * <p>It is possible for a virtual host to exist without any associated {@link PartialURL}.
   * In this case, links to it will use the canonical {@link PartialURL}, if present,
   * but the host is not matched and served locally.</p>
   */
  public DomainName getDomain() {
    return domain;
  }

  /**
   * A virtual host always has a canonical partial URL.  This is used to generate
   * URLs to the virtual host when there is no matching {@link Environment environment}.
   *
   * <p>This canonical partial URL may have {@code null} fields, which will be taken from
   * the current {@link HttpServletRequest request} via {@link HttpServletRequestFieldSource}.</p>
   */
  public PartialURL getCanonicalPartialURL() {
    return canonicalPartialUrl;
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
  private final Iterable<Rule> rulesIter = rules::iterator;

  /**
   * Gets an unmodifiable iterator to the rules.
   *
   * <p><b>Implementation Note:</b><br>
   * Is unmodifiable due to being implemented as {@link CopyOnWriteArrayList#iterator()}.</p>
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

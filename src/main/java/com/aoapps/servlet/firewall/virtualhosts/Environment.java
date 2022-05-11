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

import com.aoapps.collections.AoCollections;
import com.aoapps.lang.NullArgumentException;
import com.aoapps.net.DomainName;
import com.aoapps.net.partialurl.PartialURL;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * An {@link Environment} is a mapping between {@link PartialURL partial URLs} and {@link VirtualHost virtual hosts}.
 */
// TODO: Per-environment attributes?
public class Environment {

  private final VirtualHostManager manager;
  private final String name;
  private final Map<PartialURL, DomainName> byPartialUrl = new LinkedHashMap<>();
  // TODO: Primary is a bit redundant with byVirtualHost, since it just contains the first one added (at this time)
  private final Map<DomainName, PartialURL> primary = new LinkedHashMap<>();
  // Each value is unmodifiable and is re-created when updated
  private final Map<DomainName, Set<PartialURL>> byVirtualHost = new LinkedHashMap<>();

  Environment(VirtualHostManager manager, String name) {
    this.manager = NullArgumentException.checkNotNull(manager, "manager");
    this.name = NullArgumentException.checkNotNull(name, "name");
  }

  @Override
  public String toString() {
    return name;
  }

  public VirtualHostManager getManager() {
    return manager;
  }

  /**
   * Gets the unique name of this environment.
   */
  public String getName() {
    return name;
  }

  /**
   * Adds new mappings to this environment.
   * All {@link VirtualHost virtual hosts} referenced by the environment must already exist.
   *
   * @see  VirtualHostManager#getVirtualHost(com.aoapps.net.DomainName)
   * @see  VirtualHostManager#addSearchOrder(com.aoapps.net.partialurl.PartialURL, com.aoapps.servlet.firewall.virtualhosts.Environment, com.aoapps.net.DomainName)
   *
   * @throws  IllegalStateException  If the virtual host does not exist or the environment already contains any of the new {@link PartialURL partial URLs}.
   */
  // TODO: Overload with Mapping DomainName -> Iterable<PartialURL>?
  public Environment add(Map<? extends PartialURL, ? extends DomainName> newMappings) {
    manager.writeLock.lock();
    try {
      // Note: Virtual hosts are add-only, so they cannot be removed during this process so no need to lock the manager
      Map<PartialURL, DomainName> verified = AoCollections.newLinkedHashMap(newMappings.size());
      for (Map.Entry<? extends PartialURL, ? extends DomainName> entry : newMappings.entrySet()) {
        PartialURL partialUrl = entry.getKey();
        if (byPartialUrl.containsKey(partialUrl)) {
          throw new IllegalStateException("Mapping already exists with partial URL: " + partialUrl);
        }
        DomainName domain = entry.getValue();
        if (manager.getVirtualHost(domain) == null) {
          throw new IllegalStateException("Virtual host does not exist: " + domain);
        }
        if (verified.put(partialUrl, domain) != null) {
          throw new AssertionError();
        }
      }
      // Add now that the input is verified
      for (Map.Entry<PartialURL, DomainName> entry : verified.entrySet()) {
        PartialURL partialUrl = entry.getKey();
        DomainName domain = entry.getValue();
        if (byPartialUrl.put(partialUrl, domain) != null) {
          throw new AssertionError();
        }
        if (!primary.containsKey(domain) && primary.put(domain, partialUrl) != null) {
          throw new AssertionError();
        }
        Set<PartialURL> oldPartialUrls = byVirtualHost.get(domain);
        Set<PartialURL> unmodifiablePartialUrls;
        if (oldPartialUrls == null) {
          unmodifiablePartialUrls = Collections.singleton(partialUrl);
        } else {
          Set<PartialURL> newPartialUrls = AoCollections.newLinkedHashSet(oldPartialUrls.size() + 1);
          newPartialUrls.addAll(oldPartialUrls);
          if (!newPartialUrls.add(partialUrl)) {
            throw new AssertionError();
          }
          unmodifiablePartialUrls = Collections.unmodifiableSet(newPartialUrls);
        }
        byVirtualHost.put(domain, unmodifiablePartialUrls);
        manager.addSearchOrder(partialUrl, this, domain);
      }
    } finally {
      manager.writeLock.unlock();
    }
    return this;
  }

  /**
   * Adds new mappings to this environment.
   *
   * @param  domain       The {@link VirtualHost virtual host} must already exist.
   * @param  partialUrls  May not be empty.  Duplicate values are not OK.
   *                      The first {@link PartialURL partial URL} for a given domain is the {@link #getPrimary(com.aoapps.net.DomainName) primary}.
   *
   * @see  VirtualHostManager#getVirtualHost(com.aoapps.net.DomainName)
   *
   * @throws  IllegalArgumentException  when {@code partialURLs} contains duplicate values
   *
   * @throws  IllegalStateException  If the virtual host does not exist or the environment already contains any of the new {@link PartialURL partial URLs}.
   */
  public Environment add(DomainName domain, Iterable<? extends PartialURL> partialUrls) throws IllegalArgumentException, IllegalStateException {
    Map<PartialURL, DomainName> map = new LinkedHashMap<>();
    for (PartialURL partialUrl : partialUrls) {
      if (map.put(partialUrl, domain) != null) {
        throw new IllegalArgumentException("Duplicate partial URL: " + partialUrl);
      }
    }
    if (map.isEmpty()) {
      throw new IllegalArgumentException("No partial URLs provided");
    }
    return add(map);
  }

  /**
   * Adds new mappings to this environment.
   *
   * @param  domain       The {@link VirtualHost virtual host} must already exist.
   * @param  partialUrls  May not be empty.  Duplicate values are not OK.
   *                      The first {@link PartialURL partial URL} for a given domain is the {@link #getPrimary(com.aoapps.net.DomainName) primary}.
   *
   * @see  VirtualHostManager#getVirtualHost(com.aoapps.net.DomainName)
   *
   * @throws  IllegalArgumentException  when {@code partialURLs} contains duplicate values
   *
   * @throws  IllegalStateException  If the virtual host does not exist or the environment already contains any of the new {@link PartialURL partial URLs}.
   */
  public Environment add(DomainName domain, PartialURL ... partialUrls) throws IllegalArgumentException, IllegalStateException {
    return add(domain, Arrays.asList(partialUrls));
  }

  /**
   * Gets the primary partial URL for the given virtual host.
   * This is the same as the first partial URL from {@link #getPartialURLs(com.aoapps.net.DomainName)}.
   *
   * @return  the primary partial URL or {@code null} when the virtual host has not been added to this environment.
   *
   * @see  #getPartialURLs(com.aoapps.net.DomainName)
   */
  public PartialURL getPrimary(DomainName domain) {
    manager.readLock.lock();
    try {
      return primary.get(domain);
    } finally {
      manager.readLock.unlock();
    }
  }

  /**
   * Gets an unmodifiable copy of all the partial URLs registered for a given virtual host.
   * The first partial URL is the {@link #getPrimary(com.aoapps.net.DomainName) primary}.
   *
   * @return  the set of partial URLs or an empty set when the virtual host has not been added to this environment.
   */
  public Set<PartialURL> getPartialURLs(DomainName domain) {
    Set<PartialURL> partialUrls;
    manager.readLock.lock();
    try {
      partialUrls = byVirtualHost.get(domain);
    } finally {
      manager.readLock.unlock();
    }
    if (partialUrls == null) {
      return Collections.emptySet();
    } else {
      return partialUrls;
    }
  }
}

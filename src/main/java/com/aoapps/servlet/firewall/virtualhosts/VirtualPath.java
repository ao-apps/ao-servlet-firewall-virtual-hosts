/*
 * ao-servlet-firewall-virtual-hosts - Virtual host support for servlet-based application request filtering.
 * Copyright (C) 2018, 2021, 2022, 2024  AO Industries, Inc.
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
import com.aoapps.net.Path;

/**
 * A {@link VirtualPath} contains the domain of a {@link VirtualHost} and the {@link Path}
 * within the virtual host.
 */
public class VirtualPath implements Comparable<VirtualPath> {

  private final DomainName domain;
  private final Path path;

  /**
   * Creates a new {@link VirtualPath}.
   */
  public VirtualPath(DomainName domain, Path path) {
    this.domain = domain;
    this.path = path;
  }

  @Override
  public String toString() {
    String domainStr = domain.toString();
    String pathStr = path.toString();
    int toStringLen =
        domainStr.length()
            + 1 // ':'
            + pathStr.length();
    String toString = new StringBuilder(toStringLen)
        .append(domainStr)
        .append(':')
        .append(pathStr)
        .toString();
    assert toStringLen == toString.length();
    return toString;
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof VirtualPath)) {
      return false;
    }
    VirtualPath other = (VirtualPath) obj;
    return
        domain.equals(other.domain)
            && path.equals(other.path);
  }

  @Override
  public int hashCode() {
    return
        domain.hashCode() * 31
            + path.hashCode();
  }

  @Override
  public int compareTo(VirtualPath other) {
    int diff = domain.compareTo(other.domain);
    if (diff != 0) {
      return diff;
    }
    return path.compareTo(other.path);
  }

  public DomainName getDomain() {
    return domain;
  }

  public Path getPath() {
    return path;
  }
}

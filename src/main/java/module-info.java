/*
 * ao-servlet-firewall-virtual-hosts - Virtual host support for servlet-based application request filtering.
 * Copyright (C) 2021, 2022  AO Industries, Inc.
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
module com.aoapps.servlet.firewall.virtualhosts {
  exports com.aoapps.servlet.firewall.virtualhosts;
  // Direct
  requires com.aoapps.collections; // <groupId>com.aoapps</groupId><artifactId>ao-collections</artifactId>
  requires com.aoapps.hodgepodge; // <groupId>com.aoapps</groupId><artifactId>ao-hodgepodge</artifactId>
  requires com.aoapps.lang; // <groupId>com.aoapps</groupId><artifactId>ao-lang</artifactId>
  requires com.aoapps.net.partialurl; // <groupId>com.aoapps</groupId><artifactId>ao-net-partial-url</artifactId>
  requires com.aoapps.net.partialurl.servlet; // <groupId>com.aoapps</groupId><artifactId>ao-net-partial-url-servlet</artifactId>
  requires com.aoapps.net.types; // <groupId>com.aoapps</groupId><artifactId>ao-net-types</artifactId>
  requires com.aoapps.servlet.firewall.api; // <groupId>com.aoapps</groupId><artifactId>ao-servlet-firewall-api</artifactId>
  requires com.aoapps.servlet.util; // <groupId>com.aoapps</groupId><artifactId>ao-servlet-util</artifactId>
  requires org.apache.commons.lang3; // <groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId>
  requires javax.servlet.api; // <groupId>javax.servlet</groupId><artifactId>javax.servlet-api</artifactId>
} // TODO: Avoiding rewrite-maven-plugin-4.22.2 truncation

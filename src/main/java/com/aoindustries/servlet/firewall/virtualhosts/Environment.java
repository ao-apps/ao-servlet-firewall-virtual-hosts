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
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * An {@link Environment} is a mapping between {@link URLBase URL bases} and {@link VirtualHost virtual hosts}.
 */
// TODO: Per-environment attributes?
public class Environment {

	private final VirtualHostManager manager;
	private final String name;
	private final Map<URLBase,DomainName> byBase = new LinkedHashMap<URLBase,DomainName>();
	// TODO: Primary is a bit redundant with byVirtualHost, since it just contains the first one added (at this time)
	private final Map<DomainName,URLBase> primary = new LinkedHashMap<DomainName,URLBase>();
	// Each value is unmodifiable and is re-created when updated
	private final Map<DomainName,Set<URLBase>> byVirtualHost = new LinkedHashMap<DomainName,Set<URLBase>>();

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
	 * @see  VirtualHostManager#getVirtualHost(com.aoindustries.net.DomainName)
	 * @see  VirtualHostManager#addSearchOrder(com.aoindustries.servlet.firewall.virtualhosts.URLBase, com.aoindustries.servlet.firewall.virtualhosts.Environment, com.aoindustries.net.DomainName)
	 *
	 * @throws  IllegalStateException  If the virtual host does not exist or the environment already contains any of the new bases.
	 */
	// TODO: Overload with Mapping DomainName -> Iterable<URLBase>?
	public Environment add(Map<? extends URLBase,? extends DomainName> newMappings) {
		manager.writeLock.lock();
		try {
			// Note: Virtual hosts are add-only, so they cannot be removed during this process so no need to lock the manager
			Map<URLBase,DomainName> verified = new LinkedHashMap<URLBase,DomainName>(newMappings.size()*4/3+1);
			for(Map.Entry<? extends URLBase,? extends DomainName> entry : newMappings.entrySet()) {
				URLBase base = entry.getKey();
				if(byBase.containsKey(base)) {
					throw new IllegalStateException("Mapping already exists with base: " + base);
				}
				DomainName domain = entry.getValue();
				if(manager.getVirtualHost(domain) == null) {
					throw new IllegalStateException("Virtual host does not exist: " + domain);
				}
				if(verified.put(base, domain) != null) throw new AssertionError();
			}
			// Add now that the input is verified
			for(Map.Entry<URLBase,DomainName> entry : verified.entrySet()) {
				URLBase base = entry.getKey();
				DomainName domain = entry.getValue();
				if(byBase.put(base, domain) != null) throw new AssertionError();
				if(!primary.containsKey(domain) && primary.put(domain, base) != null) throw new AssertionError();
				Set<URLBase> oldBases = byVirtualHost.get(domain);
				Set<URLBase> unmodifiableBases;
				if(oldBases == null) {
					unmodifiableBases = Collections.singleton(base);
				} else {
					Set<URLBase> newBases = new LinkedHashSet<URLBase>((oldBases.size() + 1)*4/3+1);
					newBases.addAll(oldBases);
					if(!newBases.add(base)) throw new AssertionError();
					unmodifiableBases = Collections.unmodifiableSet(newBases);
				}
				byVirtualHost.put(domain, unmodifiableBases);
				manager.addSearchOrder(base, this, domain);
			}
		} finally {
			manager.writeLock.unlock();
		}
		return this;
	}

	/**
	 * Adds new mappings to this environment.
	 *
	 * @param  domain   The {@link VirtualHost virtual host} must already exist.
	 * @param  bases    May not be empty.  Duplicate values are not OK.
	 *                  The first {@link URLBase urlBase} for a given domain is the {@link #getPrimary(com.aoindustries.net.DomainName) primary}.
	 *
	 * @see  VirtualHostManager#getVirtualHost(com.aoindustries.net.DomainName)
	 *
	 * @throws  IllegalArgumentException  when {@code urlBases} contains duplicate values
	 *
	 * @throws  IllegalStateException  If the virtual host does not exist or the environment already contains any of the new bases.
	 */
	public Environment add(DomainName domain, Iterable<? extends URLBase> bases) throws IllegalArgumentException, IllegalStateException {
		Map<URLBase,DomainName> map = new LinkedHashMap<URLBase,DomainName>();
		for(URLBase base : bases) {
			if(map.put(base, domain) != null) throw new IllegalArgumentException("Duplicate base: " + base);
		}
		if(map.isEmpty()) throw new IllegalArgumentException("No bases provided");
		return add(map);
	}

	/**
	 * Adds new mappings to this environment.
	 *
	 * @param  domain   The {@link VirtualHost virtual host} must already exist.
	 * @param  bases    May not be empty.  Duplicate values are not OK.
	 *                  The first {@link URLBase urlBase} for a given domain is the {@link #getPrimary(com.aoindustries.net.DomainName) primary}.
	 *
	 * @see  VirtualHostManager#getVirtualHost(com.aoindustries.net.DomainName)
	 *
	 * @throws  IllegalArgumentException  when {@code urlBases} contains duplicate values
	 *
	 * @throws  IllegalStateException  If the virtual host does not exist or the environment already contains any of the new bases.
	 */
	public Environment add(DomainName domain, URLBase ... bases) throws IllegalArgumentException, IllegalStateException {
		return add(domain, Arrays.asList(bases));
	}

	/**
	 * Gets the primary base for the given virtual host.
	 * This is the same as the first base from {@link #getBases(com.aoindustries.net.DomainName)}.
	 *
	 * @return  the primary base or {@code null} when the virtual host has not been added to this environment.
	 *
	 * @see  #getBases(com.aoindustries.net.DomainName)
	 */
	public URLBase getPrimary(DomainName domain) {
		manager.readLock.lock();
		try {
			return primary.get(domain);
		} finally {
			manager.readLock.unlock();
		}
	}

	/**
	 * Gets an unmodifiable copy of all the bases registered for a given virtual host.
	 * The first base is the {@link #getPrimary(com.aoindustries.net.DomainName) primary}.
	 *
	 * @return  the set of bases or an empty set when the virtual host has not been added to this environment.
	 */
	public Set<URLBase> getBases(DomainName domain) {
		Set<URLBase> bases;
		manager.readLock.lock();
		try {
			bases = byVirtualHost.get(domain);
		} finally {
			manager.readLock.unlock();
		}
		if(bases == null) return Collections.emptySet();
		else return bases;
	}
}

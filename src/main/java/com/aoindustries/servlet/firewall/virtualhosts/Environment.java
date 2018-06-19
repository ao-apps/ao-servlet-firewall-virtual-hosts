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
import com.aoindustries.net.partialurl.PartialURL;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * An {@link Environment} is a mapping between {@link PartialURL partial URLs} and {@link VirtualHost virtual hosts}.
 */
// TODO: Per-environment attributes?
public class Environment {

	private final VirtualHostManager manager;
	private final String name;
	private final Map<PartialURL,DomainName> byPartialURL = new LinkedHashMap<PartialURL,DomainName>();
	// TODO: Primary is a bit redundant with byVirtualHost, since it just contains the first one added (at this time)
	private final Map<DomainName,PartialURL> primary = new LinkedHashMap<DomainName,PartialURL>();
	// Each value is unmodifiable and is re-created when updated
	private final Map<DomainName,Set<PartialURL>> byVirtualHost = new LinkedHashMap<DomainName,Set<PartialURL>>();

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
	 * @see  VirtualHostManager#addSearchOrder(com.aoindustries.net.partialurl.PartialURL, com.aoindustries.servlet.firewall.virtualhosts.Environment, com.aoindustries.net.DomainName)
	 *
	 * @throws  IllegalStateException  If the virtual host does not exist or the environment already contains any of the new {@link PartialURL partial URLs}.
	 */
	// TODO: Overload with Mapping DomainName -> Iterable<PartialURL>?
	public Environment add(Map<? extends PartialURL,? extends DomainName> newMappings) {
		manager.writeLock.lock();
		try {
			// Note: Virtual hosts are add-only, so they cannot be removed during this process so no need to lock the manager
			Map<PartialURL,DomainName> verified = new LinkedHashMap<PartialURL,DomainName>(newMappings.size()*4/3+1);
			for(Map.Entry<? extends PartialURL,? extends DomainName> entry : newMappings.entrySet()) {
				PartialURL partialURL = entry.getKey();
				if(byPartialURL.containsKey(partialURL)) {
					throw new IllegalStateException("Mapping already exists with partial URL: " + partialURL);
				}
				DomainName domain = entry.getValue();
				if(manager.getVirtualHost(domain) == null) {
					throw new IllegalStateException("Virtual host does not exist: " + domain);
				}
				if(verified.put(partialURL, domain) != null) throw new AssertionError();
			}
			// Add now that the input is verified
			for(Map.Entry<PartialURL,DomainName> entry : verified.entrySet()) {
				PartialURL partialURL = entry.getKey();
				DomainName domain = entry.getValue();
				if(byPartialURL.put(partialURL, domain) != null) throw new AssertionError();
				if(!primary.containsKey(domain) && primary.put(domain, partialURL) != null) throw new AssertionError();
				Set<PartialURL> oldPartialURLs = byVirtualHost.get(domain);
				Set<PartialURL> unmodifiablePartialURLs;
				if(oldPartialURLs == null) {
					unmodifiablePartialURLs = Collections.singleton(partialURL);
				} else {
					Set<PartialURL> newPartialURLs = new LinkedHashSet<PartialURL>((oldPartialURLs.size() + 1)*4/3+1);
					newPartialURLs.addAll(oldPartialURLs);
					if(!newPartialURLs.add(partialURL)) throw new AssertionError();
					unmodifiablePartialURLs = Collections.unmodifiableSet(newPartialURLs);
				}
				byVirtualHost.put(domain, unmodifiablePartialURLs);
				manager.addSearchOrder(partialURL, this, domain);
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
	 * @param  partialURLs  May not be empty.  Duplicate values are not OK.
	 *                      The first {@link PartialURL partial URL} for a given domain is the {@link #getPrimary(com.aoindustries.net.DomainName) primary}.
	 *
	 * @see  VirtualHostManager#getVirtualHost(com.aoindustries.net.DomainName)
	 *
	 * @throws  IllegalArgumentException  when {@code partialURLs} contains duplicate values
	 *
	 * @throws  IllegalStateException  If the virtual host does not exist or the environment already contains any of the new {@link PartialURL partial URLs}.
	 */
	public Environment add(DomainName domain, Iterable<? extends PartialURL> partialURLs) throws IllegalArgumentException, IllegalStateException {
		Map<PartialURL,DomainName> map = new LinkedHashMap<PartialURL,DomainName>();
		for(PartialURL partialURL : partialURLs) {
			if(map.put(partialURL, domain) != null) throw new IllegalArgumentException("Duplicate partial URL: " + partialURL);
		}
		if(map.isEmpty()) throw new IllegalArgumentException("No partial URLs provided");
		return add(map);
	}

	/**
	 * Adds new mappings to this environment.
	 *
	 * @param  domain       The {@link VirtualHost virtual host} must already exist.
	 * @param  partialURLs  May not be empty.  Duplicate values are not OK.
	 *                      The first {@link PartialURL partial URL} for a given domain is the {@link #getPrimary(com.aoindustries.net.DomainName) primary}.
	 *
	 * @see  VirtualHostManager#getVirtualHost(com.aoindustries.net.DomainName)
	 *
	 * @throws  IllegalArgumentException  when {@code partialURLs} contains duplicate values
	 *
	 * @throws  IllegalStateException  If the virtual host does not exist or the environment already contains any of the new {@link PartialURL partial URLs}.
	 */
	public Environment add(DomainName domain, PartialURL ... partialURLs) throws IllegalArgumentException, IllegalStateException {
		return add(domain, Arrays.asList(partialURLs));
	}

	/**
	 * Gets the primary partial URL for the given virtual host.
	 * This is the same as the first partial URL from {@link #getPartialURLs(com.aoindustries.net.DomainName)}.
	 *
	 * @return  the primary partial URL or {@code null} when the virtual host has not been added to this environment.
	 *
	 * @see  #getPartialURLs(com.aoindustries.net.DomainName)
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
	 * The first partial URL is the {@link #getPrimary(com.aoindustries.net.DomainName) primary}.
	 *
	 * @return  the set of partial URLs or an empty set when the virtual host has not been added to this environment.
	 */
	public Set<PartialURL> getPartialURLs(DomainName domain) {
		Set<PartialURL> partialURLs;
		manager.readLock.lock();
		try {
			partialURLs = byVirtualHost.get(domain);
		} finally {
			manager.readLock.unlock();
		}
		if(partialURLs == null) return Collections.emptySet();
		else return partialURLs;
	}
}

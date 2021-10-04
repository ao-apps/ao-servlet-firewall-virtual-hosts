/*
 * ao-servlet-firewall-virtual-hosts - Virtual host support for servlet-based application request filtering.
 * Copyright (C) 2018, 2020, 2021  AO Industries, Inc.
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
package com.aoapps.servlet.firewall.virtualhosts;

import com.aoapps.hodgepodge.util.WildcardPatternMatcher;
import com.aoapps.lang.validation.ValidationException;
import com.aoapps.net.Path;
import com.aoapps.servlet.attribute.ScopeEE;
import com.aoapps.servlet.firewall.api.Action;
import com.aoapps.servlet.firewall.api.FirewallContext;
import com.aoapps.servlet.firewall.api.Matcher;
import com.aoapps.servlet.firewall.api.Matcher.Result;
import static com.aoapps.servlet.firewall.api.MatcherUtil.doMatches;
import com.aoapps.servlet.firewall.api.Rule;
import java.io.IOException;
import java.util.Arrays;
import java.util.regex.Pattern;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.NotImplementedException;

/**
 * A set of {@link Matcher} and {@link Action} implementations for {@link VirtualHostManager} and {@link VirtualHostMatch}.
 *
 * <p>
 * <b>Implementation Note:</b><br>
 * This is admittedly overload-heavy.  We are paying the price here in order to have the absolutely
 * cleanest possible rule definitions.  Perhaps a future version of Java will introduce optional parameters
 * and this can be cleaned-up some.
 * </p>
 */
public class Rules {

	private Rules() {}

	// <editor-fold defaultstate="collapsed" desc="virtualHostManager">
	/**
	 * @see  VirtualHostManager
	 */
	public static class virtualHostManager {

		private virtualHostManager() {}

		/**
		 * TODO
		 */
		public static final Matcher doVirtualHost = (context, request) -> {
			throw new NotImplementedException("TODO");
		};
	}
	// </editor-fold>

	// <editor-fold defaultstate="collapsed" desc="virtualHostMatch">
	/**
	 * @see  VirtualHostMatch
	 */
	public static class virtualHostMatch {

		// TODO: Redirect to primary
		// TODO: Redirect to canonical
		// TODO: ao-servlet-fireall-virtual-hosts.xml?
		// TODO: environment selectors, not just partial URLs?  Like by username/hostname/... arbitrary expression?

		private virtualHostMatch() {}

		/**
		 * The request key that holds the current {@link VirtualHostMatch}.
		 */
		private static final ScopeEE.Request.Attribute<VirtualHostMatch> VIRTUAL_HOST_MATCH_REQUEST_KEY =
			ScopeEE.REQUEST.attribute(virtualHostMatch.class.getName());

		/**
		 * Gets the {@link VirtualHostMatch} for the current request.
		 *
		 * @throws ServletException when no {@link VirtualHostMatch} set.
		 */
		// TODO: Should this be on FirewallContext only instead of the request?
		private static VirtualHostMatch getVirtualHostMatch(ServletRequest request) throws ServletException {
			VirtualHostMatch virtualHostMatch = VIRTUAL_HOST_MATCH_REQUEST_KEY.context(request).get();
			if(virtualHostMatch == null) throw new ServletException("VirtualHostMatch not set on request");
			return virtualHostMatch;
		}

		private abstract static class VirtualHostMatchMatcher implements Matcher {
			@Override
			public final Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
				VirtualHostMatch virtualHostMatch = getVirtualHostMatch(request);
				if(
					matches(
						context,
						request,
						virtualHostMatch
					)
				) {
					return Result.MATCH;
				} else {
					return Result.NO_MATCH;
				}
			}

			/**
			 * @see  #perform(com.aoapps.servlet.firewall.api.FirewallContext, javax.servlet.http.HttpServletRequest)
			 */
			protected abstract boolean matches(
				FirewallContext context,
				HttpServletRequest request,
				VirtualHostMatch virtualHostMatch
			) throws IOException, ServletException;
		}

		private abstract static class VirtualHostMatchMatcherWithRules implements Matcher {

			private final Iterable<? extends Rule> rules;

			private VirtualHostMatchMatcherWithRules(Iterable<? extends Rule> rules) {
				this.rules = rules;
			}

			//private VirtualHostMatchMatcherWithRules(Rule ... rules) {
			//	this(Arrays.asList(rules));
			//}

			@Override
			public final Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
				VirtualHostMatch virtualHostMatch = getVirtualHostMatch(request);
				return doMatches(
					matches(
						context,
						request,
						virtualHostMatch
					),
					context,
					rules
				);
			}

			/**
			 * @see  #perform(com.aoapps.servlet.firewall.api.FirewallContext, javax.servlet.http.HttpServletRequest)
			 */
			protected abstract boolean matches(
				FirewallContext context,
				HttpServletRequest request,
				VirtualHostMatch virtualHostMatch
			) throws IOException, ServletException;
		}

		private abstract static class VirtualHostMatchMatcherWithRulesAndOtherwise implements Matcher {

			private final Iterable<? extends Rule> rules;
			private final Iterable<? extends Rule> otherwise;

			private VirtualHostMatchMatcherWithRulesAndOtherwise(Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				this.rules = rules;
				this.otherwise = otherwise;
			}

			//private VirtualHostMatchMatcherWithRulesAndOtherwise(Rule[] rules, Rule ... otherwise) {
			//	this(Arrays.asList(rules), Arrays.asList(otherwise));
			//}

			@Override
			public final Result perform(FirewallContext context, HttpServletRequest request) throws IOException, ServletException {
				VirtualHostMatch virtualHostMatch = getVirtualHostMatch(request);
				return doMatches(
					matches(
						context,
						request,
						virtualHostMatch
					),
					context,
					rules,
					otherwise
				);
			}

			/**
			 * @see  #perform(com.aoapps.servlet.firewall.api.FirewallContext, javax.servlet.http.HttpServletRequest)
			 */
			protected abstract boolean matches(
				FirewallContext context,
				HttpServletRequest request,
				VirtualHostMatch virtualHostMatch
			) throws IOException, ServletException;
		}

		// <editor-fold defaultstate="collapsed" desc="environment">
		/**
		 * @see  VirtualHostMatch#getEnvironment()
		 */
		public static class environment {

			private environment() {}

			// TODO
		}
		// </editor-fold>

		// <editor-fold defaultstate="collapsed" desc="partialURL">
		/**
		 * @see  VirtualHostMatch#getPartialURL()
		 */
		public static class partialURL {

			private partialURL() {}

			// TODO
		}
		// </editor-fold>

		// <editor-fold defaultstate="collapsed" desc="url">
		/**
		 * @see  VirtualHostMatch#getUrl()
		 */
		public static class url {

			private url() {}

			// TODO
		}
		// </editor-fold>

		// <editor-fold defaultstate="collapsed" desc="virtualHost">
		/**
		 * @see  VirtualHostMatch#getVirtualHost()
		 */
		public static class virtualHost {

			private virtualHost() {}

			// TODO
		}
		// </editor-fold>

		// <editor-fold defaultstate="collapsed" desc="virtualPath">
		/**
		 * @see  VirtualHostMatch#getVirtualPath()
		 */
		public static class virtualPath {

			private virtualPath() {}

			// TODO: domain?

			/**
			 * Matches when the virtual path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(final String prefix) {
				return new VirtualHostMatchMatcher() {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return virtualHostMatch.getVirtualPath().getPath().toString().startsWith(prefix);
					}
				};
			}

			/**
			 * Matches when the virtual path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(final String prefix, Iterable<? extends Rule> rules) {
				return new VirtualHostMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return virtualHostMatch.getVirtualPath().getPath().toString().startsWith(prefix);
					}
				};
			}

			/**
			 * Matches when the virtual path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(final String prefix, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new VirtualHostMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return virtualHostMatch.getVirtualPath().getPath().toString().startsWith(prefix);
					}
				};
			}

			/**
			 * Matches when the virtual path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(String prefix, Rule ... rules) {
				if(rules.length == 0) return startsWith(prefix);
				return startsWith(prefix, Arrays.asList(rules));
			}

			/**
			 * Matches when the virtual path starts with a given string, case-sensitive.
			 * Matches when prefix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#startsWith(java.lang.String)
			 */
			public static Matcher startsWith(String prefix, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return startsWith(prefix, rules);
				return startsWith(prefix, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches when the virtual path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(final String suffix) {
				return new VirtualHostMatchMatcher() {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return virtualHostMatch.getVirtualPath().getPath().toString().endsWith(suffix);
					}
				};
			}

			/**
			 * Matches when the virtual path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(final String suffix, Iterable<? extends Rule> rules) {
				return new VirtualHostMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return virtualHostMatch.getVirtualPath().getPath().toString().endsWith(suffix);
					}
				};
			}

			/**
			 * Matches when the virtual path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(final String suffix, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new VirtualHostMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return virtualHostMatch.getVirtualPath().getPath().toString().endsWith(suffix);
					}
				};
			}

			/**
			 * Matches when the virtual path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(String suffix, Rule ... rules) {
				if(rules.length == 0) return endsWith(suffix);
				return endsWith(suffix, Arrays.asList(rules));
			}

			/**
			 * Matches when the virtual path ends with a given string, case-sensitive.
			 * Matches when suffix is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#endsWith(java.lang.String)
			 */
			public static Matcher endsWith(String suffix, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return endsWith(suffix, rules);
				return endsWith(suffix, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches when the virtual path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(final CharSequence substring) {
				return new VirtualHostMatchMatcher() {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return virtualHostMatch.getVirtualPath().getPath().toString().contains(substring);
					}
				};
			}

			/**
			 * Matches when the virtual path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(final CharSequence substring, Iterable<? extends Rule> rules) {
				return new VirtualHostMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return virtualHostMatch.getVirtualPath().getPath().toString().contains(substring);
					}
				};
			}

			/**
			 * Matches when the virtual path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(final CharSequence substring, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new VirtualHostMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return virtualHostMatch.getVirtualPath().getPath().toString().contains(substring);
					}
				};
			}

			/**
			 * Matches when the virtual path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(CharSequence substring, Rule ... rules) {
				if(rules.length == 0) return contains(substring);
				return contains(substring, Arrays.asList(rules));
			}

			/**
			 * Matches when the virtual path contains a given character sequence, case-sensitive.
			 * Matches when substring is empty.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#contains(java.lang.CharSequence)
			 */
			public static Matcher contains(CharSequence substring, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return contains(substring, rules);
				return contains(substring, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches when the virtual path is equal to a given string, case-sensitive.
			 *
			 * @see  Path#equals(java.lang.Object)
			 */
			public static Matcher equals(final Path target) {
				return new VirtualHostMatchMatcher() {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return virtualHostMatch.getVirtualPath().getPath().equals(target);
					}
				};
			}

			/**
			 * Matches when the virtual path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Path#equals(java.lang.Object)
			 */
			public static Matcher equals(final Path target, Iterable<? extends Rule> rules) {
				return new VirtualHostMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return virtualHostMatch.getVirtualPath().getPath().equals(target);
					}
				};
			}

			/**
			 * Matches when the virtual path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Path#equals(java.lang.Object)
			 */
			public static Matcher equals(final Path target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new VirtualHostMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return virtualHostMatch.getVirtualPath().getPath().equals(target);
					}
				};
			}

			/**
			 * Matches when the virtual path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Path#equals(java.lang.Object)
			 */
			public static Matcher equals(Path target, Rule ... rules) {
				if(rules.length == 0) return equals(target);
				return equals(target, Arrays.asList(rules));
			}

			/**
			 * Matches when the virtual path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Path#equals(java.lang.Object)
			 */
			public static Matcher equals(Path target, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return equals(target, rules);
				return equals(target, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches when the virtual path is equal to a given string, case-sensitive.
			 *
			 * @see  Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target) {
				try {
					return equals(Path.valueOf(target));
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when the virtual path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Iterable<? extends Rule> rules) {
				try {
					return equals(Path.valueOf(target), rules);
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when the virtual path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				try {
					return equals(Path.valueOf(target), rules, otherwise);
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when the virtual path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Rule ... rules) {
				try {
					return equals(Path.valueOf(target), rules);
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			// TODO: Support a "map" instead of just "equals", to avoid sequential lookups when there are a large number of different specific targets.

			/**
			 * Matches when the virtual path is equal to a given string, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Path#valueOf(java.lang.String)
			 */
			public static Matcher equals(String target, Rule[] rules, Rule ... otherwise) {
				try {
					return equals(Path.valueOf(target), rules, otherwise);
				} catch(ValidationException e) {
					throw new IllegalArgumentException(e);
				}
			}

			/**
			 * Matches when the virtual path is equal to a given character sequence, case-sensitive.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target) {
				return new VirtualHostMatchMatcher() {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return virtualHostMatch.getVirtualPath().getPath().toString().contentEquals(target);
					}
				};
			}

			/**
			 * Matches when the virtual path is equal to a given character sequence, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target, Iterable<? extends Rule> rules) {
				return new VirtualHostMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return virtualHostMatch.getVirtualPath().getPath().toString().contentEquals(target);
					}
				};
			}

			/**
			 * Matches when the virtual path is equal to a given character sequence, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(final CharSequence target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new VirtualHostMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return virtualHostMatch.getVirtualPath().getPath().toString().contentEquals(target);
					}
				};
			}

			/**
			 * Matches when the virtual path is equal to a given character sequence, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(CharSequence target, Rule ... rules) {
				if(rules.length == 0) return equals(target);
				return equals(target, Arrays.asList(rules));
			}

			/**
			 * Matches when the virtual path is equal to a given character sequence, case-sensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#contentEquals(java.lang.CharSequence)
			 */
			public static Matcher equals(CharSequence target, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return equals(target, rules);
				return equals(target, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches when the virtual path is equal to a given string, case-insensitive.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target) {
				return new VirtualHostMatchMatcher() {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return virtualHostMatch.getVirtualPath().getPath().toString().equalsIgnoreCase(target);
					}
				};
			}

			/**
			 * Matches when the virtual path is equal to a given string, case-insensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target, Iterable<? extends Rule> rules) {
				return new VirtualHostMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return virtualHostMatch.getVirtualPath().getPath().toString().equalsIgnoreCase(target);
					}
				};
			}

			/**
			 * Matches when the virtual path is equal to a given string, case-insensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(final String target, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new VirtualHostMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return virtualHostMatch.getVirtualPath().getPath().toString().equalsIgnoreCase(target);
					}
				};
			}

			/**
			 * Matches when the virtual path is equal to a given string, case-insensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(String target, Rule ... rules) {
				if(rules.length == 0) return equalsIgnoreCase(target);
				return equalsIgnoreCase(target, Arrays.asList(rules));
			}

			/**
			 * Matches when the virtual path is equal to a given string, case-insensitive.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  String#equalsIgnoreCase(java.lang.String)
			 */
			public static Matcher equalsIgnoreCase(String target, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return equalsIgnoreCase(target, rules);
				return equalsIgnoreCase(target, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches when the virtual path matches a given regular expression.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(final Pattern pattern) {
				return new VirtualHostMatchMatcher() {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return pattern.matcher(virtualHostMatch.getVirtualPath().getPath().toString()).matches();
					}
				};
			}

			/**
			 * Matches when the virtual path matches a given regular expression.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(final Pattern pattern, Iterable<? extends Rule> rules) {
				return new VirtualHostMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return pattern.matcher(virtualHostMatch.getVirtualPath().getPath().toString()).matches();
					}
				};
			}

			/**
			 * Matches when the virtual path matches a given regular expression.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(final Pattern pattern, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new VirtualHostMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return pattern.matcher(virtualHostMatch.getVirtualPath().getPath().toString()).matches();
					}
				};
			}

			/**
			 * Matches when the virtual path matches a given regular expression.
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(Pattern pattern, Rule ... rules) {
				if(rules.length == 0) return matches(pattern);
				return matches(pattern, Arrays.asList(rules));
			}

			/**
			 * Matches when the virtual path matches a given regular expression.
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  Pattern#compile(java.lang.String)
			 * @see  Pattern#compile(java.lang.String, int)
			 */
			public static Matcher matches(Pattern pattern, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return matches(pattern, rules);
				return matches(pattern, Arrays.asList(rules), Arrays.asList(otherwise));
			}

			/**
			 * Matches when the virtual path matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 * <p>
			 * TODO: Move {@link WildcardPatternMatcher} to own microproject and remove dependency on larger ao-hodgepodge project.
			 * </p>
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(final WildcardPatternMatcher wildcardPattern) {
				return new VirtualHostMatchMatcher() {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return wildcardPattern.isMatch(virtualHostMatch.getVirtualPath().getPath().toString());
					}
				};
			}

			/**
			 * Matches when the virtual path matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(final WildcardPatternMatcher wildcardPattern, Iterable<? extends Rule> rules) {
				return new VirtualHostMatchMatcherWithRules(rules) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return wildcardPattern.isMatch(virtualHostMatch.getVirtualPath().getPath().toString());
					}
				};
			}

			/**
			 * Matches when the virtual path matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(final WildcardPatternMatcher wildcardPattern, Iterable<? extends Rule> rules, Iterable<? extends Rule> otherwise) {
				return new VirtualHostMatchMatcherWithRulesAndOtherwise(rules, otherwise) {
					@Override
					protected boolean matches(FirewallContext context, HttpServletRequest request, VirtualHostMatch virtualHostMatch) {
						return wildcardPattern.isMatch(virtualHostMatch.getVirtualPath().getPath().toString());
					}
				};
			}

			/**
			 * Matches when the virtual path matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @param  rules  Invoked only when matched.
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(WildcardPatternMatcher wildcardPattern, Rule ... rules) {
				if(rules.length == 0) return matches(wildcardPattern);
				return matches(wildcardPattern, Arrays.asList(rules));
			}

			/**
			 * Matches when the virtual path matches a given {@link WildcardPatternMatcher}.
			 * <p>
			 * {@link WildcardPatternMatcher} can significantly outperform {@link Pattern},
			 * especially in suffix matching.
			 * </p>
			 *
			 * @param  rules  Invoked only when matched.
			 * @param  otherwise  Invoked only when not matched.
			 *
			 * @see  WildcardPatternMatcher#compile(java.lang.String)
			 */
			public static Matcher matches(WildcardPatternMatcher wildcardPattern, Rule[] rules, Rule ... otherwise) {
				if(otherwise.length == 0) return matches(wildcardPattern, rules);
				return matches(wildcardPattern, Arrays.asList(rules), Arrays.asList(otherwise));
			}
		}

		// TODO: PathMatch-compatible for non-servlet-space root? (/**, /, /servlet-path)?

		// TODO: String.regionMatches?

		// TODO: More case-insensitive of the above?

		// TODO: CompareTo for before/after/ <=, >=?

		// </editor-fold>
	}
	// </editor-fold>
}

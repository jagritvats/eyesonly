// Policy matching shared by client, server and hook.
//
// Server policy (<repo>.git/veil.json):
//   {
//     "members":  ["*"],                       who may access the repo at all
//     "admins":   ["alice"],
//     "groups":   { "core": ["alice", "bob"] },
//     "files":    { ".env": ["@core"], "secrets/**": ["@core"] },   first match wins
//     "branches": { "refs/heads/private/": ["@core"] }              longest prefix wins
//   }
//
// Client policy (.git/veil/policy.json) is a resolved view served by the
// server: { repo, user, files: { glob: [usernames] }, keys: { name: card } }.

export function globToRegex(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        if (glob[i + 2] === '/') {
          re += '(?:.*/)?';
          i += 2;
        } else {
          re += '.*';
          i += 1;
        }
      } else re += '[^/]*';
    } else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp('^' + re + '$');
}

/** Returns the principal list for the first matching file glob, or null. */
export function fileRule(policy, path) {
  for (const [glob, who] of Object.entries(policy.files || {})) {
    if (globToRegex(glob).test(path)) return who;
  }
  return null;
}

function refMatches(prefix, ref) {
  if (ref === prefix) return true;
  return prefix.endsWith('/') ? ref.startsWith(prefix) : ref.startsWith(prefix + '/');
}

/** Returns { prefix, who } for the longest matching branch rule, or null (= public ref). */
export function refRule(policy, ref) {
  let best = null;
  for (const [prefix, who] of Object.entries(policy.branches || {})) {
    if (refMatches(prefix, ref) && (!best || prefix.length > best.prefix.length)) best = { prefix, who };
  }
  return best;
}

/** Expand ["*", "@group", "name"] into a Set of user names. */
// Names that aren't registered users are dropped: they can't authenticate, and keeping
// them would make every other audience look "narrower" (e.g. a branch rule naming a
// not-yet-registered user would make main look narrower than that branch).
export function expand(policy, principals, allUsers) {
  const known = new Set(allUsers);
  const out = new Set();
  const add = (u) => known.has(u) && out.add(u);
  for (const p of principals || []) {
    if (p === '*') allUsers.forEach(add);
    else if (p.startsWith('@')) (policy.groups?.[p.slice(1)] || []).forEach(add);
    else add(p);
  }
  return out;
}

export function isSubset(a, b) {
  for (const x of a) if (!b.has(x)) return false;
  return true;
}

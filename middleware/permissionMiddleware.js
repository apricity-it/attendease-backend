const pool = require("../config/db");

const permissionCache = new Map();
let cacheVersion = 0;

const buildCacheKey = (userId) => `${userId}:${cacheVersion}`;

const invalidatePermissionCache = () => {
  cacheVersion += 1;
  permissionCache.clear();
};

const fetchUserPermissions = async (userId) => {
  if (!userId) {
    return { set: new Set(), cityMap: new Map() };
  }

  const cacheKey = buildCacheKey(userId);
  if (permissionCache.has(cacheKey)) {
    return permissionCache.get(cacheKey);
  }

  const query = `
    SELECT p.module, p.action, NULL::int AS city_id
    FROM permissions p
    JOIN role_permissions rp ON rp.permission_id = p.id
    JOIN user_roles ur ON ur.role_id = rp.role_id
    WHERE ur.user_id = $1
    UNION ALL
    SELECT p.module, p.action, up.city_id
    FROM permissions p
    JOIN user_permissions up ON up.permission_id = p.id
    WHERE up.user_id = $1
  `;

  const { rows } = await pool.query(query, [userId]);

  const permissionSet = new Set();
  const cityMap = new Map();

  rows.forEach((row) => {
    const key = `${row.module}:${row.action}`.toLowerCase();
    permissionSet.add(key);

    if (!cityMap.has(key)) {
      cityMap.set(key, { all: false, ids: new Set() });
    }

    const scope = cityMap.get(key);
    if (row.city_id === null || row.city_id === undefined) {
      scope.all = true;
      scope.ids.clear();
    } else if (!scope.all) {
      scope.ids.add(row.city_id);
    }
  });

  const payload = { set: permissionSet, cityMap };
  permissionCache.set(cacheKey, payload);
  return payload;
};

const authorize = (requiredModule, requiredAction) => {
  return async (req, res, next) => {
    try {
      const userId = req.user?.user_id;

      if (!userId) {
        return res
          .status(401)
          .json({ error: "Unauthorized: user context missing" });
      }

      // Admins always pass
      if (req.user?.role === "admin") {
        return next();
      }

      const permissionPayload = await fetchUserPermissions(userId);
      const requiredKey = `${requiredModule}:${requiredAction}`.toLowerCase();
      const candidateKeys =
        requiredAction === "view"
          ? [requiredKey, `${requiredModule}:write`.toLowerCase()]
          : [requiredKey];

      const matchedKey = candidateKeys.find((candidate) =>
        permissionPayload.set.has(candidate)
      );

      if (!matchedKey) {
        return res
          .status(403)
          .json({
            error: "Forbidden: missing permission",
            permission: requiredKey,
          });
      }

      if (!req.permissionScopes) {
        req.permissionScopes = {};
      }
      if (!req.permissionScopes[matchedKey]) {
        const scope = permissionPayload.cityMap.get(matchedKey);
        if (scope) {
          req.permissionScopes[matchedKey] = {
            all: scope.all,
            ids: new Set(scope.ids),
          };
        }
      }

      return next();
    } catch (error) {
      console.error("Permission check failed:", error);
      return res.status(500).json({ error: "Permission check failed" });
    }
  };
};

const getPermissionCityFilter = (req, module, action) => {
  const key = `${module}:${action}`.toLowerCase();
  const fallbackKey =
    action === "view" ? `${module}:write`.toLowerCase() : null;
  const scope =
    req.permissionScopes?.[key] ||
    (fallbackKey ? req.permissionScopes?.[fallbackKey] : null);
  if (!scope || scope.all || !scope.ids || scope.ids.size === 0) {
    return null;
  }
  return Array.from(scope.ids);
};

module.exports = {
  authorize,
  fetchUserPermissions,
  invalidatePermissionCache,
  getPermissionCityFilter,
};

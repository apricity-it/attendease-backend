const pool = require("../config/db");

const cityAccessCache = new Map();
let cityAccessVersion = 0;

const buildCacheKey = (userId) => `${userId || "unknown"}:${cityAccessVersion}`;

const invalidateCityAccessCache = () => {
  cityAccessVersion += 1;
  cityAccessCache.clear();
};

const normalizeCityIds = (cityIds = []) => {
  const seen = new Set();
  const normalized = [];

  (cityIds || []).forEach((raw) => {
    const value = Number(raw);
    if (Number.isFinite(value) && !seen.has(value)) {
      seen.add(value);
      normalized.push(value);
    }
  });

  return normalized;
};

const fetchUserCityAccess = async (user, options = {}) => {
  const userId =
    (typeof user === "object" && user !== null ? user.user_id : null) ||
    Number(user) ||
    null;
  const role =
    (typeof user === "object" && user !== null ? user.role : null) || null;
  const includeCityMetadata = options.includeCities || options.withNames;

  if (!userId) {
    return { all: false, ids: [], cities: [] };
  }

  if (role && typeof role === "string" && role.toLowerCase() === "admin") {
    if (includeCityMetadata) {
      const { rows } = await pool.query(
        "SELECT city_id, city_name FROM cities ORDER BY city_name ASC"
      );
      const ids = normalizeCityIds(rows.map((row) => row.city_id));
      return { all: true, ids, cities: rows };
    }
    return { all: true, ids: [] };
  }

  const cacheKey = buildCacheKey(userId);
  if (!includeCityMetadata && cityAccessCache.has(cacheKey)) {
    return cityAccessCache.get(cacheKey);
  }

  const queryText = includeCityMetadata
    ? `
        SELECT c.city_id, c.city_name
        FROM user_city_access uca
        JOIN cities c ON c.city_id = uca.city_id
        WHERE uca.user_id = $1
        ORDER BY c.city_name ASC
      `
    : `
        SELECT city_id
        FROM user_city_access
        WHERE user_id = $1
      `;

  const { rows } = await pool.query(queryText, [userId]);
  const ids = normalizeCityIds(
    includeCityMetadata ? rows.map((row) => row.city_id) : rows.map((row) => row.city_id)
  );

  const payload = includeCityMetadata
    ? { all: false, ids, cities: rows }
    : { all: false, ids };

  if (!includeCityMetadata) {
    cityAccessCache.set(cacheKey, payload);
  }

  return payload;
};

const syncUserCityAccess = async (
  userId,
  cityIds = [],
  actorId = null,
  client = pool
) => {
  const ids = normalizeCityIds(cityIds);

  await client.query("DELETE FROM user_city_access WHERE user_id = $1", [
    userId,
  ]);

  if (ids.length === 0) {
    invalidateCityAccessCache();
    return;
  }

  await client.query(
    `
      INSERT INTO user_city_access (user_id, city_id, granted_at, granted_by)
      SELECT $1, UNNEST($2::int[]), NOW(), $3
      ON CONFLICT DO NOTHING
    `,
    [userId, ids, actorId ?? null]
  );

  invalidateCityAccessCache();
};

module.exports = {
  fetchUserCityAccess,
  normalizeCityIds,
  syncUserCityAccess,
  invalidateCityAccessCache,
};

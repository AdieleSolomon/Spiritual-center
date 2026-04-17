import express from "express";
import { createPool as createMySqlPool } from "mysql2/promise";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import multer from "multer";
import { join, extname } from "path";
import cors from "cors";
import { existsSync, mkdirSync, unlinkSync, readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname } from "path";
import dotenv from "dotenv";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

// Initialize dotenv
dotenv.config();

const { Pool: PostgresPool } = pg;

const app = express();
const PORT = process.env.PORT || 5501;
const POSTGRES_PROVIDER_ALIASES = new Set([
  "postgres",
  "postgresql",
  "supabase",
  "railway",
  "railway-postgres",
]);
const MYSQL_PROVIDER_ALIASES = new Set(["mysql", "laragon"]);

const resolveDbProvider = () => {
  const rawProvider = (process.env.DB_PROVIDER || "").toLowerCase().trim();

  if (POSTGRES_PROVIDER_ALIASES.has(rawProvider)) {
    return "postgres";
  }

  if (MYSQL_PROVIDER_ALIASES.has(rawProvider)) {
    return "mysql";
  }

  // Auto-detect based on connection string if provider is not explicitly set
  const connectionString = (
    process.env.DATABASE_URL ||
    process.env.DATABASE_PUBLIC_URL ||
    ""
  ).toLowerCase();

  if (
    connectionString.startsWith("postgres://") ||
    connectionString.startsWith("postgresql://")
  ) {
    return "postgres";
  }

  if (connectionString.startsWith("mysql://")) {
    return "mysql";
  }

  if (rawProvider) {
    console.warn(
      `Unknown DB_PROVIDER "${rawProvider}". Falling back to mysql (Laragon).`,
    );
  }
  return "mysql";
};

const DB_PROVIDER = resolveDbProvider();
const IS_POSTGRES = DB_PROVIDER === "postgres";

const parseBoolean = (value, defaultValue = false) => {
  if (value === undefined || value === null || value === "") {
    return defaultValue;
  }

  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
};

const DEFAULT_MAX_UPLOAD_SIZE_BYTES = 100 * 1024 * 1024;

const parseByteSize = (
  value,
  fallbackValue = DEFAULT_MAX_UPLOAD_SIZE_BYTES,
) => {
  if (value === undefined || value === null || value === "") {
    return fallbackValue;
  }

  const normalized = String(value).trim().toLowerCase();
  const directNumber = Number(normalized);
  if (Number.isFinite(directNumber) && directNumber > 0) {
    return Math.floor(directNumber);
  }

  const unitMatch = normalized.match(/^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)$/i);
  if (!unitMatch) {
    return fallbackValue;
  }

  const numericPart = Number(unitMatch[1]);
  const unit = unitMatch[2].toLowerCase();
  const multipliers = {
    b: 1,
    kb: 1024,
    mb: 1024 * 1024,
    gb: 1024 * 1024 * 1024,
  };

  return Math.floor(numericPart * (multipliers[unit] || 1));
};

const JWT_SECRET = process.env.JWT_SECRET || "spiritual-center-secret-key-2024";
const PASSWORD_RESET_TOKEN_TTL_MINUTES = Number(
  process.env.PASSWORD_RESET_TOKEN_TTL_MINUTES || 30,
);
const ALLOW_PLAINTEXT_RESET_TOKEN = parseBoolean(
  process.env.ALLOW_PLAINTEXT_RESET_TOKEN,
  true,
);

const normalizeEmail = (value = "") => String(value).trim().toLowerCase();
const normalizeUsername = (value = "") => String(value).trim();
const normalizeOptionalUrl = (value = "") => {
  const normalized = String(value || "").trim();
  return normalized || null;
};
const isValidEmail = (value = "") =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value).trim());
const isStrongPassword = (value = "") => String(value).length >= 8;
const isValidYouTubeUrl = (value = "") => {
  const normalized = normalizeOptionalUrl(value);
  if (!normalized) return true;

  try {
    const parsed = new URL(normalized);
    const protocol = parsed.protocol.toLowerCase();
    const hostname = parsed.hostname.toLowerCase();

    if (!["http:", "https:"].includes(protocol)) {
      return false;
    }

    return (
      hostname === "youtu.be" ||
      hostname.endsWith(".youtu.be") ||
      hostname === "youtube.com" ||
      hostname.endsWith(".youtube.com") ||
      hostname === "youtube-nocookie.com" ||
      hostname.endsWith(".youtube-nocookie.com")
    );
  } catch (error) {
    return false;
  }
};

const DEFAULT_MATERIAL_YOUTUBE_OVERRIDES = new Map([
  [
    "worship songs|worship|audio",
    "https://youtu.be/2I47CEc264w?si=7uJ53KkO_98kQ3Ch",
  ],
]);

const resolveMaterialYouTubeUrl = (material = {}) => {
  const explicitUrl = normalizeOptionalUrl(material.youtube_url);
  if (explicitUrl) {
    return explicitUrl;
  }

  const fallbackKey = [material.title, material.category, material.type]
    .map((value) =>
      String(value || "")
        .trim()
        .toLowerCase(),
    )
    .join("|");

  return DEFAULT_MATERIAL_YOUTUBE_OVERRIDES.get(fallbackKey) || null;
};

const hashRecoveryToken = (rawToken) =>
  crypto.createHash("sha256").update(String(rawToken)).digest("hex");

const createRecoveryToken = () => {
  const rawToken = crypto.randomBytes(24).toString("hex");
  const hashedToken = hashRecoveryToken(rawToken);
  const expiresAt = new Date(
    Date.now() + PASSWORD_RESET_TOKEN_TTL_MINUTES * 60 * 1000,
  );

  return {
    rawToken,
    hashedToken,
    expiresAt,
  };
};

const signAuthToken = (user) =>
  jwt.sign(
    {
      userId: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
    },
    JWT_SECRET,
    { expiresIn: "24h" },
  );

const parseCsvEnv = (value = "") =>
  String(value)
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

const configuredCorsOrigins = new Set(
  [
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:5501",
    "http://127.0.0.1:5501",
    process.env.FRONTEND_URL,
    ...parseCsvEnv(process.env.CORS_ORIGINS),
  ].filter(Boolean),
);

const isAllowedCorsOrigin = (origin) => {
  if (!origin) {
    return true;
  }

  if (configuredCorsOrigins.has(origin)) {
    return true;
  }

  try {
    const { hostname } = new URL(origin);
    if (hostname.endsWith(".vercel.app")) {
      return true;
    }
  } catch (error) {
    return false;
  }

  return false;
};

// Get __dirname equivalent for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Middleware
app.use(
  cors({
    origin: (origin, callback) => {
      if (isAllowedCorsOrigin(origin)) {
        return callback(null, true);
      }

      return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
  }),
);
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));
app.use(express.static("public"));
app.use("/uploads", express.static("uploads"));

// Security middleware
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  }),
);
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
  }),
);

const mysqlConfig = {
  host:
    process.env.LARAGON_HOST ||
    process.env.DB_HOST ||
    process.env.MYSQLHOST ||
    "localhost",
  user:
    process.env.LARAGON_USER ||
    process.env.DB_USER ||
    process.env.MYSQLUSER ||
    "root",
  password:
    process.env.LARAGON_PASSWORD ||
    process.env.DB_PASSWORD ||
    process.env.MYSQLPASSWORD ||
    "",
  database:
    process.env.LARAGON_DATABASE ||
    process.env.DB_NAME ||
    process.env.MYSQLDATABASE ||
    "spiritual_center",
  port: Number(
    process.env.LARAGON_PORT ||
      process.env.DB_PORT ||
      process.env.MYSQLPORT ||
      3306,
  ),
  waitForConnections: true,
  connectionLimit: Number(process.env.DB_CONNECTION_LIMIT || 10),
  queueLimit: 0,
  charset: "utf8mb4",
};

if (parseBoolean(process.env.DB_SSL, false)) {
  mysqlConfig.ssl = { rejectUnauthorized: false };
}

const postgresSslEnabled = parseBoolean(
  process.env.POSTGRES_SSL ??
    process.env.DATABASE_SSL ??
    process.env.SUPABASE_DB_SSL ??
    process.env.DB_SSL,
  true,
);

const postgresConnectionString =
  process.env.DATABASE_URL ||
  process.env.DATABASE_PUBLIC_URL ||
  process.env.POSTGRES_URL ||
  process.env.POSTGRES_CONNECTION_STRING ||
  process.env.SUPABASE_DATABASE_URL;

const postgresConfig = postgresConnectionString
  ? {
      connectionString: postgresConnectionString,
      max: Number(process.env.DB_CONNECTION_LIMIT || 10),
      ssl: postgresSslEnabled ? { rejectUnauthorized: false } : false,
    }
  : {
      host:
        process.env.PGHOST ||
        process.env.POSTGRES_HOST ||
        process.env.SUPABASE_DB_HOST ||
        "localhost",
      user:
        process.env.PGUSER ||
        process.env.POSTGRES_USER ||
        process.env.SUPABASE_DB_USER ||
        "postgres",
      password:
        process.env.PGPASSWORD ||
        process.env.POSTGRES_PASSWORD ||
        process.env.SUPABASE_DB_PASSWORD ||
        "",
      database:
        process.env.PGDATABASE ||
        process.env.POSTGRES_DB ||
        process.env.SUPABASE_DB_NAME ||
        "postgres",
      port: Number(
        process.env.PGPORT ||
          process.env.POSTGRES_PORT ||
          process.env.SUPABASE_DB_PORT ||
          5432,
      ),
      max: Number(process.env.DB_CONNECTION_LIMIT || 10),
      ssl: postgresSslEnabled ? { rejectUnauthorized: false } : false,
    };

const resolveSupabaseUrl = () => {
  const explicitUrl = String(
    process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || "",
  )
    .trim()
    .replace(/\/+$/, "");

  if (explicitUrl) {
    return explicitUrl;
  }

  const candidateConnectionString = process.env.SUPABASE_DATABASE_URL || "";
  if (!candidateConnectionString) {
    return "";
  }

  try {
    const parsedUrl = new URL(candidateConnectionString);
    const decodedUsername = decodeURIComponent(parsedUrl.username || "");
    const usernameMatch = decodedUsername.match(/^[^.]+\.([a-z0-9]{6,})$/i);
    if (usernameMatch?.[1]) {
      return `https://${usernameMatch[1].toLowerCase()}.supabase.co`;
    }

    const hostMatch = parsedUrl.hostname.match(
      /^db\.([a-z0-9]{6,})\.supabase\.co$/i,
    );
    if (hostMatch?.[1]) {
      return `https://${hostMatch[1].toLowerCase()}.supabase.co`;
    }
  } catch (error) {
    console.warn(
      "Failed to derive SUPABASE_URL from connection string:",
      error.message,
    );
  }

  return "";
};

const SUPABASE_URL = resolveSupabaseUrl();
const SUPABASE_STORAGE_ENABLED = parseBoolean(
  process.env.SUPABASE_STORAGE_ENABLED,
  true,
);
const SUPABASE_SERVICE_ROLE_KEY = String(
  process.env.SUPABASE_SERVICE_ROLE_KEY || "",
).trim();
const SUPABASE_ANON_KEY = String(process.env.SUPABASE_ANON_KEY || "").trim();
const SUPABASE_STORAGE_BUCKET = String(
  process.env.SUPABASE_STORAGE_BUCKET || "materials",
).trim();
const SUPABASE_STORAGE_FOLDER = String(
  process.env.SUPABASE_STORAGE_FOLDER || "materials",
).trim();
const MAX_UPLOAD_SIZE_BYTES = parseByteSize(
  process.env.MAX_UPLOAD_SIZE_BYTES,
  DEFAULT_MAX_UPLOAD_SIZE_BYTES,
);
const SUPABASE_STORAGE_FILE_SIZE_LIMIT = parseByteSize(
  process.env.SUPABASE_STORAGE_FILE_SIZE_LIMIT,
  MAX_UPLOAD_SIZE_BYTES,
);
const SUPABASE_STORAGE_BUCKET_PUBLIC = parseBoolean(
  process.env.SUPABASE_STORAGE_BUCKET_PUBLIC,
  true,
);
const REQUIRE_PERSISTENT_STORAGE = parseBoolean(
  process.env.REQUIRE_PERSISTENT_STORAGE,
  IS_POSTGRES,
);
const SUPABASE_STORAGE_API_KEY =
  SUPABASE_SERVICE_ROLE_KEY ||
  (!REQUIRE_PERSISTENT_STORAGE ? SUPABASE_ANON_KEY : "");
const SUPABASE_REQUEST_API_KEY = SUPABASE_ANON_KEY || SUPABASE_STORAGE_API_KEY;
let supabaseBucketVerified = false;

if (SUPABASE_STORAGE_ENABLED && (!SUPABASE_URL || !SUPABASE_STORAGE_API_KEY)) {
  if (REQUIRE_PERSISTENT_STORAGE) {
    console.warn(
      "Supabase Storage is not fully configured. Uploads will be blocked until storage credentials are set or REQUIRE_PERSISTENT_STORAGE is disabled.",
    );
  } else {
    console.warn(
      "Supabase Storage is not fully configured. Uploads will fall back to local /uploads storage.",
    );
  }
}

const toPostgresPlaceholders = (sql) => {
  let paramIndex = 0;
  return sql.replace(/\?/g, () => `$${++paramIndex}`);
};

const normalizePostgresSql = (sql) => {
  let normalized = sql;

  normalized = normalized.replace(
    /DATE_SUB\(\s*NOW\(\)\s*,\s*INTERVAL\s+(\d+)\s+DAY\s*\)/gi,
    "NOW() - INTERVAL '$1 day'",
  );

  normalized = normalized.replace(
    /DATE_FORMAT\(\s*([^,]+?)\s*,\s*'%Y-%m-%d %H:%i:%s'\s*\)/gi,
    "TO_CHAR($1, 'YYYY-MM-DD HH24:MI:SS')",
  );

  normalized = normalized.replace(
    /HOUR\(\s*([^)]+?)\s*\)/gi,
    "EXTRACT(HOUR FROM $1)",
  );

  return normalized;
};

const appendReturningId = (sql) => {
  if (!/^\s*INSERT\s+INTO/i.test(sql) || /\bRETURNING\b/i.test(sql)) {
    return sql;
  }

  return `${sql.trim().replace(/;$/, "")} RETURNING id`;
};

const executePostgresQuery = async (target, sql, params = []) => {
  const isInsert = /^\s*INSERT\s+INTO/i.test(sql);
  let transformedSql = normalizePostgresSql(sql);
  transformedSql = toPostgresPlaceholders(transformedSql);
  transformedSql = isInsert
    ? appendReturningId(transformedSql)
    : transformedSql;

  const result = await target.query(transformedSql, params);

  if (isInsert) {
    return [
      {
        insertId: result.rows[0]?.id ?? null,
        affectedRows: result.rowCount,
      },
    ];
  }

  return [result.rows];
};

const createDatabasePool = () => {
  if (IS_POSTGRES) {
    const postgresPool = new PostgresPool(postgresConfig);

    return {
      execute: (sql, params = []) =>
        executePostgresQuery(postgresPool, sql, params),
      getConnection: async () => {
        const client = await postgresPool.connect();
        return {
          execute: (sql, params = []) =>
            executePostgresQuery(client, sql, params),
          release: () => client.release(),
        };
      },
      end: () => postgresPool.end(),
    };
  }

  return createMySqlPool(mysqlConfig);
};

const pool = createDatabasePool();

const normalizePathSlashes = (value = "") => String(value).replace(/\\/g, "/");

const trimEdgeSlashes = (value = "") => String(value).replace(/^\/+|\/+$/g, "");

const sanitizePathSegment = (value = "", fallback = "file") => {
  const normalized = String(value)
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");

  return normalized || fallback;
};

const encodeStoragePath = (storagePath = "") =>
  normalizePathSlashes(storagePath)
    .split("/")
    .filter(Boolean)
    .map((segment) => encodeURIComponent(segment))
    .join("/");

const decodeStoragePath = (storagePath = "") => {
  try {
    return decodeURIComponent(storagePath);
  } catch (error) {
    return storagePath;
  }
};

const isSupabaseStorageConfigured = () =>
  SUPABASE_STORAGE_ENABLED &&
  Boolean(SUPABASE_URL) &&
  Boolean(SUPABASE_STORAGE_BUCKET) &&
  Boolean(SUPABASE_STORAGE_API_KEY);

const buildSupabaseObjectPath = (file, materialType = "file") => {
  const fileExtension =
    extname(file?.originalname || file?.filename || "").toLowerCase() || "";
  const objectName = `${Date.now()}-${crypto.randomBytes(6).toString("hex")}${fileExtension}`;
  const folderParts = [
    trimEdgeSlashes(SUPABASE_STORAGE_FOLDER || "materials"),
    sanitizePathSegment(materialType, "file"),
  ].filter(Boolean);

  return `${folderParts.join("/")}/${objectName}`;
};

const buildSupabasePublicUrl = (objectPath = "") =>
  `${SUPABASE_URL}/storage/v1/object/public/${encodeURIComponent(SUPABASE_STORAGE_BUCKET)}/${encodeStoragePath(objectPath)}`;

const buildSupabaseAuthHeaders = (extraHeaders = {}) => {
  const headers = {
    Authorization: `Bearer ${SUPABASE_STORAGE_API_KEY}`,
    ...extraHeaders,
  };

  if (SUPABASE_REQUEST_API_KEY) {
    headers.apikey = SUPABASE_REQUEST_API_KEY;
  }

  return headers;
};

const buildSupabaseBucketConfigPayload = () => {
  const payload = {
    public: SUPABASE_STORAGE_BUCKET_PUBLIC,
  };

  if (
    Number.isFinite(SUPABASE_STORAGE_FILE_SIZE_LIMIT) &&
    SUPABASE_STORAGE_FILE_SIZE_LIMIT > 0
  ) {
    payload.file_size_limit = SUPABASE_STORAGE_FILE_SIZE_LIMIT;
  }

  return payload;
};

const isSupabaseBucketMissingError = (statusCode, details = "") => {
  if (statusCode === 404) {
    return true;
  }

  const detailsText = String(details || "");
  if (/bucket not found/i.test(detailsText)) {
    return true;
  }

  try {
    const parsed = JSON.parse(detailsText);
    const parsedStatus = Number(parsed?.statusCode || 0);
    const combinedMessage =
      `${parsed?.error || ""} ${parsed?.message || ""}`.trim();
    if (parsedStatus === 404 && /bucket/i.test(combinedMessage)) {
      return true;
    }
  } catch (error) {
    return false;
  }

  return false;
};

const isSupabaseBucketAlreadyExistsError = (details = "") => {
  const detailsText = String(details || "");
  if (/already exists|duplicate/i.test(detailsText)) {
    return true;
  }

  try {
    const parsed = JSON.parse(detailsText);
    const combinedMessage =
      `${parsed?.error || ""} ${parsed?.message || ""}`.trim();
    return /already exists|duplicate/i.test(combinedMessage);
  } catch (error) {
    return false;
  }
};

const isSupabasePayloadTooLargeError = (statusCode, details = "") => {
  if (statusCode === 413) {
    return true;
  }

  const detailsText = String(details || "");
  if (
    /payload too large|exceeded the maximum allowed size/i.test(detailsText)
  ) {
    return true;
  }

  try {
    const parsed = JSON.parse(detailsText);
    const parsedStatus = Number(parsed?.statusCode || 0);
    const combinedMessage =
      `${parsed?.error || ""} ${parsed?.message || ""}`.trim();
    return (
      parsedStatus === 413 &&
      /payload too large|exceeded the maximum allowed size/i.test(
        combinedMessage,
      )
    );
  } catch (error) {
    return false;
  }
};

const createPayloadTooLargeError = (message) => {
  const error = new Error(message);
  error.code = "PAYLOAD_TOO_LARGE";
  return error;
};

const updateSupabaseStorageBucket = async () => {
  if (!isSupabaseStorageConfigured()) {
    return;
  }

  const bucketSegment = encodeURIComponent(SUPABASE_STORAGE_BUCKET);
  const updateUrl = `${SUPABASE_URL}/storage/v1/bucket/${bucketSegment}`;
  const response = await fetch(updateUrl, {
    method: "PUT",
    headers: buildSupabaseAuthHeaders({
      "Content-Type": "application/json",
    }),
    body: JSON.stringify(buildSupabaseBucketConfigPayload()),
  });

  if (!response.ok) {
    const details = await response.text().catch(() => "");
    if (isSupabasePayloadTooLargeError(response.status, details)) {
      const requestedLimit = SUPABASE_STORAGE_FILE_SIZE_LIMIT || 0;
      throw createPayloadTooLargeError(
        `Supabase storage rejected the requested bucket file size limit (${requestedLimit} bytes). Your project likely enforces a lower per-file cap. Reduce MAX_UPLOAD_SIZE_BYTES/SUPABASE_STORAGE_FILE_SIZE_LIMIT or increase the project limit in Supabase.`,
      );
    }
    throw new Error(
      `Failed to update storage bucket "${SUPABASE_STORAGE_BUCKET}" (${response.status}): ${
        details || response.statusText
      }`,
    );
  }
};

const ensureSupabaseStorageBucket = async () => {
  if (!isSupabaseStorageConfigured() || supabaseBucketVerified) {
    return;
  }

  const bucketSegment = encodeURIComponent(SUPABASE_STORAGE_BUCKET);
  const inspectUrl = `${SUPABASE_URL}/storage/v1/bucket/${bucketSegment}`;

  const inspectResponse = await fetch(inspectUrl, {
    method: "GET",
    headers: buildSupabaseAuthHeaders(),
  });

  if (inspectResponse.ok) {
    supabaseBucketVerified = true;
    return;
  }

  const inspectDetails = await inspectResponse.text().catch(() => "");
  if (!isSupabaseBucketMissingError(inspectResponse.status, inspectDetails)) {
    throw new Error(
      `Unable to verify storage bucket "${SUPABASE_STORAGE_BUCKET}" (${inspectResponse.status}): ${
        inspectDetails || inspectResponse.statusText
      }`,
    );
  }

  const createResponse = await fetch(`${SUPABASE_URL}/storage/v1/bucket`, {
    method: "POST",
    headers: buildSupabaseAuthHeaders({
      "Content-Type": "application/json",
    }),
    body: JSON.stringify({
      id: SUPABASE_STORAGE_BUCKET,
      name: SUPABASE_STORAGE_BUCKET,
      ...buildSupabaseBucketConfigPayload(),
    }),
  });

  if (!createResponse.ok) {
    const createDetails = await createResponse.text().catch(() => "");
    if (!isSupabaseBucketAlreadyExistsError(createDetails)) {
      throw new Error(
        `Failed to create storage bucket "${SUPABASE_STORAGE_BUCKET}" (${createResponse.status}): ${
          createDetails || createResponse.statusText
        }`,
      );
    }
  }

  supabaseBucketVerified = true;
};

const safeUnlink = (filePath) => {
  if (!filePath || !existsSync(filePath)) {
    return;
  }

  try {
    unlinkSync(filePath);
  } catch (error) {
    console.warn(`Failed to remove file "${filePath}":`, error.message);
  }
};

const uploadFileToSupabaseStorage = async (file, materialType = "file") => {
  if (!isSupabaseStorageConfigured() || !file?.path) {
    return null;
  }

  const fileSize = Number(file?.size || 0);
  const objectPath = buildSupabaseObjectPath(file, materialType);
  const encodedPath = encodeStoragePath(objectPath);
  const bucketSegment = encodeURIComponent(SUPABASE_STORAGE_BUCKET);
  const uploadUrl = `${SUPABASE_URL}/storage/v1/object/${bucketSegment}/${encodedPath}`;
  const fileBuffer = readFileSync(file.path);
  const performUpload = () =>
    fetch(uploadUrl, {
      method: "POST",
      headers: buildSupabaseAuthHeaders({
        "Content-Type": file.mimetype || "application/octet-stream",
        "x-upsert": "false",
      }),
      body: fileBuffer,
    });

  let response = await performUpload();

  if (!response.ok) {
    let details = await response.text().catch(() => "");

    if (isSupabaseBucketMissingError(response.status, details)) {
      await ensureSupabaseStorageBucket();
      response = await performUpload();
      if (!response.ok) {
        details = await response.text().catch(() => "");
        throw new Error(
          `Supabase storage upload failed (${response.status}): ${details || response.statusText}`,
        );
      }
    } else if (isSupabasePayloadTooLargeError(response.status, details)) {
      await updateSupabaseStorageBucket();
      response = await performUpload();
      if (!response.ok) {
        details = await response.text().catch(() => "");
        if (isSupabasePayloadTooLargeError(response.status, details)) {
          const sizeLabel = fileSize ? `${fileSize} bytes` : "this size";
          throw createPayloadTooLargeError(
            `Supabase storage bucket "${SUPABASE_STORAGE_BUCKET}" rejected ${sizeLabel}. Increase the project/bucket file size limit or upload a smaller file.`,
          );
        }
        throw new Error(
          `Supabase storage upload failed (${response.status}): ${details || response.statusText}`,
        );
      }
    } else {
      throw new Error(
        `Supabase storage upload failed (${response.status}): ${details || response.statusText}`,
      );
    }
  }

  supabaseBucketVerified = true;

  return {
    objectPath,
    publicUrl: buildSupabasePublicUrl(objectPath),
  };
};

const deleteSupabaseObjectByPath = async (objectPath = "") => {
  if (!isSupabaseStorageConfigured() || !objectPath) {
    return false;
  }

  const encodedPath = encodeStoragePath(objectPath);
  const bucketSegment = encodeURIComponent(SUPABASE_STORAGE_BUCKET);
  const deleteUrl = `${SUPABASE_URL}/storage/v1/object/${bucketSegment}/${encodedPath}`;

  const response = await fetch(deleteUrl, {
    method: "DELETE",
    headers: buildSupabaseAuthHeaders(),
  });

  if (!response.ok && response.status !== 404) {
    const details = await response.text().catch(() => "");
    throw new Error(
      `Supabase storage delete failed (${response.status}): ${details || response.statusText}`,
    );
  }

  return true;
};

const extractSupabaseObjectPath = (fileUrl = "") => {
  if (!SUPABASE_URL || !SUPABASE_STORAGE_BUCKET || !fileUrl) {
    return null;
  }

  if (!/^https?:\/\//i.test(String(fileUrl).trim())) {
    return null;
  }

  try {
    const url = new URL(String(fileUrl).trim());
    const bucketSegment = encodeURIComponent(SUPABASE_STORAGE_BUCKET);
    const publicPrefix = `/storage/v1/object/public/${bucketSegment}/`;
    const objectPrefix = `/storage/v1/object/${bucketSegment}/`;

    if (url.pathname.startsWith(publicPrefix)) {
      return decodeStoragePath(url.pathname.slice(publicPrefix.length));
    }

    if (url.pathname.startsWith(objectPrefix)) {
      return decodeStoragePath(url.pathname.slice(objectPrefix.length));
    }
  } catch (error) {
    return null;
  }

  return null;
};

const resolveLocalUploadFilePath = (fileUrl = "") => {
  const normalized = normalizePathSlashes(String(fileUrl || "").trim());
  if (!normalized || /^https?:\/\//i.test(normalized)) {
    return null;
  }

  const relativePath = normalized.replace(/^\.?\/*/, "");
  if (!relativePath.startsWith("uploads/")) {
    return null;
  }

  return join(__dirname, relativePath);
};

const removeStoredMaterialFile = async (fileUrl = "") => {
  if (!fileUrl) {
    return;
  }

  const supabaseObjectPath = extractSupabaseObjectPath(fileUrl);
  if (supabaseObjectPath) {
    try {
      await deleteSupabaseObjectByPath(supabaseObjectPath);
      return;
    } catch (error) {
      console.warn(
        `Failed to delete Supabase object for "${fileUrl}":`,
        error.message,
      );
    }
  }

  const localFilePath = resolveLocalUploadFilePath(fileUrl);
  safeUnlink(localFilePath);
};

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error("Token verification error:", error);
    return res.status(403).json({ error: "Invalid or expired token" });
  }
};

const authenticateOptionalToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    req.user = null;
    return next();
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    return next();
  } catch (error) {
    console.error("Optional token verification error:", error);
    return res.status(403).json({ error: "Invalid or expired token" });
  }
};

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = "uploads";
    if (!existsSync(uploadDir)) {
      mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.]/g, "_");
    cb(null, `material-${uniqueSuffix}-${safeName}`);
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: MAX_UPLOAD_SIZE_BYTES },
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      "video/mp4",
      "video/quicktime",
      "video/x-msvideo",
      "video/x-matroska",
      "video/mkv",
      "video/avi",
      "video/mov",
      "video/webm",
      "image/jpeg",
      "image/png",
      "image/gif",
      "image/webp",
      "image/svg+xml",
      "audio/mpeg",
      "audio/wav",
      "audio/ogg",
      "application/pdf",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "text/plain",
      "application/zip",
      "application/x-rar-compressed",
    ];

    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid file type: ${file.mimetype}`), false);
    }
  },
});

// ==================== DATABASE INITIALIZATION ====================
const UPSERT_SETTING_SQL = IS_POSTGRES
  ? `
      INSERT INTO settings (setting_key, setting_value, setting_type)
      VALUES (?, ?, ?)
      ON CONFLICT (setting_key) DO UPDATE
      SET setting_value = EXCLUDED.setting_value,
          setting_type = EXCLUDED.setting_type
    `
  : `
      INSERT INTO settings (setting_key, setting_value, setting_type)
      VALUES (?, ?, ?)
      ON DUPLICATE KEY UPDATE
        setting_value = VALUES(setting_value),
        setting_type = VALUES(setting_type)
    `;

const INSERT_DEFAULT_SETTING_SQL = IS_POSTGRES
  ? `
      INSERT INTO settings (setting_key, setting_value, setting_type)
      VALUES (?, ?, ?)
      ON CONFLICT (setting_key) DO NOTHING
    `
  : `
      INSERT INTO settings (setting_key, setting_value, setting_type)
      VALUES (?, ?, ?)
      ON DUPLICATE KEY UPDATE
        setting_key = setting_key
    `;

const DEFAULT_SETTINGS = [
  ["site_title", "Spiritual Center", "string"],
  [
    "site_description",
    "Center of Knowledge and Spiritual Enrichment",
    "string",
  ],
  ["contact_email", "admin@spiritualcenter.com", "string"],
  ["contact_phone", "+234 907 256 0420", "string"],
  ["whatsapp_number", "+2349072560420", "string"],
  ["support_heading", "Support the Ministry", "string"],
  [
    "support_intro",
    "Your support helps sustain biblical teaching, prayer care, counseling, outreach, and ministry media.",
    "string",
  ],
  ["support_currency", "NGN", "string"],
  ["support_bank_name", "OPay", "string"],
  ["support_account_name", "", "string"],
  ["support_account_number", "8069383370", "string"],
  [
    "support_payment_note",
    "After sending your support, reach the ministry through WhatsApp or email with your transfer details so it can be confirmed quickly.",
    "string",
  ],
  ["support_payment_link", "", "string"],
  ["support_email", "admin@spiritualcenter.com", "string"],
  ["support_whatsapp", "+2349072560420", "string"],
  ["max_upload_size", "104857600", "number"],
  [
    "allowed_file_types",
    '["pdf","doc","docx","jpg","jpeg","png","gif","mp4","avi","mov","mp3","wav"]',
    "json",
  ],
];

const PUBLIC_SUPPORT_SETTING_KEYS = [
  "site_title",
  "contact_email",
  "contact_phone",
  "whatsapp_number",
  "support_heading",
  "support_intro",
  "support_currency",
  "support_bank_name",
  "support_account_name",
  "support_account_number",
  "support_payment_note",
  "support_payment_link",
  "support_email",
  "support_whatsapp",
];

const postgresSchemaStatements = [
  `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) NOT NULL UNIQUE,
      email VARCHAR(255) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      reset_password_token VARCHAR(128),
      reset_password_expires TIMESTAMP,
      role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'admin')),
      is_approved BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  "CREATE INDEX IF NOT EXISTS idx_users_email ON users (email)",
  "CREATE INDEX IF NOT EXISTS idx_users_role ON users (role)",
  `
    CREATE TABLE IF NOT EXISTS materials (
      id SERIAL PRIMARY KEY,
      title VARCHAR(500) NOT NULL,
      description TEXT,
      category VARCHAR(100),
      type VARCHAR(20) NOT NULL CHECK (type IN ('document', 'image', 'video', 'audio', 'writeup')),
      file_url VARCHAR(1000),
      youtube_url VARCHAR(1000),
      file_name VARCHAR(255),
      file_size INTEGER,
      is_public BOOLEAN DEFAULT TRUE,
      uploader_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      views INTEGER DEFAULT 0,
      downloads INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  "CREATE INDEX IF NOT EXISTS idx_materials_category ON materials (category)",
  "CREATE INDEX IF NOT EXISTS idx_materials_type ON materials (type)",
  "CREATE INDEX IF NOT EXISTS idx_materials_public ON materials (is_public)",
  "CREATE INDEX IF NOT EXISTS idx_materials_search ON materials USING GIN (to_tsvector('english', COALESCE(title, '') || ' ' || COALESCE(description, '')))",
  `
    CREATE TABLE IF NOT EXISTS prayer_requests (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      email VARCHAR(255),
      whatsapp_number VARCHAR(50),
      request TEXT NOT NULL,
      is_anonymous BOOLEAN DEFAULT FALSE,
      status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'read', 'responded')),
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  "CREATE INDEX IF NOT EXISTS idx_prayer_status ON prayer_requests (status)",
  "CREATE INDEX IF NOT EXISTS idx_prayer_created ON prayer_requests (created_at)",
  `
    CREATE TABLE IF NOT EXISTS counseling_requests (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      counseling_type VARCHAR(100) NOT NULL,
      whatsapp_number VARCHAR(50),
      description TEXT NOT NULL,
      preferred_availability VARCHAR(255),
      status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'scheduled', 'completed', 'cancelled')),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  "CREATE INDEX IF NOT EXISTS idx_counseling_status ON counseling_requests (status)",
  "CREATE INDEX IF NOT EXISTS idx_counseling_user_id ON counseling_requests (user_id)",
  `
    CREATE TABLE IF NOT EXISTS daily_promises (
      id SERIAL PRIMARY KEY,
      promise_text TEXT NOT NULL,
      author VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  "CREATE INDEX IF NOT EXISTS idx_daily_promises_created ON daily_promises (created_at)",
  `
    CREATE TABLE IF NOT EXISTS devotion_posts (
      id SERIAL PRIMARY KEY,
      title VARCHAR(255),
      devotion_text TEXT NOT NULL,
      author VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  "CREATE INDEX IF NOT EXISTS idx_devotion_posts_created ON devotion_posts (created_at)",
  `
    CREATE TABLE IF NOT EXISTS comments (
      id SERIAL PRIMARY KEY,
      post_type VARCHAR(50) NOT NULL,
      post_id INTEGER NOT NULL,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      comment_text TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  "CREATE INDEX IF NOT EXISTS idx_comments_post ON comments (post_type, post_id)",
  "CREATE INDEX IF NOT EXISTS idx_comments_created ON comments (created_at)",
  `
    CREATE TABLE IF NOT EXISTS donations (
      id SERIAL PRIMARY KEY,
      amount DECIMAL(10,2) NOT NULL,
      currency VARCHAR(10) DEFAULT 'USD',
      donor_name VARCHAR(255) NOT NULL,
      donor_email VARCHAR(255) NOT NULL,
      message TEXT,
      payment_method VARCHAR(50) NOT NULL,
      transaction_id VARCHAR(100) UNIQUE,
      status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed')),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  "CREATE INDEX IF NOT EXISTS idx_donations_status ON donations (status)",
  "CREATE INDEX IF NOT EXISTS idx_donations_email ON donations (donor_email)",
  `
    CREATE TABLE IF NOT EXISTS analytics (
      id SERIAL PRIMARY KEY,
      event_type VARCHAR(50) NOT NULL,
      event_data JSONB,
      user_id INTEGER,
      user_agent TEXT,
      ip_address VARCHAR(45),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  "CREATE INDEX IF NOT EXISTS idx_analytics_event_type ON analytics (event_type)",
  "CREATE INDEX IF NOT EXISTS idx_analytics_created ON analytics (created_at)",
  `
    CREATE TABLE IF NOT EXISTS settings (
      id SERIAL PRIMARY KEY,
      setting_key VARCHAR(100) NOT NULL UNIQUE,
      setting_value TEXT,
      setting_type VARCHAR(20) DEFAULT 'string' CHECK (setting_type IN ('string', 'number', 'boolean', 'json')),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  "CREATE INDEX IF NOT EXISTS idx_settings_key ON settings (setting_key)",
];

const ensureUserAuthColumns = async (connection) => {
  if (IS_POSTGRES) {
    await connection.execute(
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_password_token VARCHAR(128)",
    );
    await connection.execute(
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_password_expires TIMESTAMP",
    );
    return;
  }

  try {
    await connection.execute(
      "ALTER TABLE users ADD COLUMN reset_password_token VARCHAR(128) NULL",
    );
  } catch (error) {
    if (error?.code !== "ER_DUP_FIELDNAME") {
      throw error;
    }
  }

  try {
    await connection.execute(
      "ALTER TABLE users ADD COLUMN reset_password_expires TIMESTAMP NULL",
    );
  } catch (error) {
    if (error?.code !== "ER_DUP_FIELDNAME") {
      throw error;
    }
  }
};

const ensureDonationColumns = async (connection) => {
  if (IS_POSTGRES) {
    await connection.execute(
      "ALTER TABLE donations ADD COLUMN IF NOT EXISTS donor_phone VARCHAR(50)",
    );
    await connection.execute(
      "ALTER TABLE donations ADD COLUMN IF NOT EXISTS support_type VARCHAR(80)",
    );
    await connection.execute(
      "ALTER TABLE donations ADD COLUMN IF NOT EXISTS frequency VARCHAR(30) DEFAULT 'one_time'",
    );
    await connection.execute(
      "ALTER TABLE donations ADD COLUMN IF NOT EXISTS is_anonymous BOOLEAN DEFAULT FALSE",
    );
    await connection.execute(
      "ALTER TABLE donations ADD COLUMN IF NOT EXISTS admin_note TEXT",
    );
    await connection.execute(
      "ALTER TABLE donations ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
    );
    return;
  }

  const alterStatements = [
    "ALTER TABLE donations ADD COLUMN donor_phone VARCHAR(50) NULL",
    "ALTER TABLE donations ADD COLUMN support_type VARCHAR(80) NULL",
    "ALTER TABLE donations ADD COLUMN frequency VARCHAR(30) NOT NULL DEFAULT 'one_time'",
    "ALTER TABLE donations ADD COLUMN is_anonymous BOOLEAN DEFAULT FALSE",
    "ALTER TABLE donations ADD COLUMN admin_note TEXT NULL",
    "ALTER TABLE donations ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP",
  ];

  for (const statement of alterStatements) {
    try {
      await connection.execute(statement);
    } catch (error) {
      if (error?.code !== "ER_DUP_FIELDNAME") {
        throw error;
      }
    }
  }
};

const ensureMaterialColumns = async (connection) => {
  if (IS_POSTGRES) {
    await connection.execute(
      "ALTER TABLE materials ADD COLUMN IF NOT EXISTS youtube_url VARCHAR(1000)",
    );
    return;
  }

  try {
    await connection.execute(
      "ALTER TABLE materials ADD COLUMN youtube_url VARCHAR(1000) NULL",
    );
  } catch (error) {
    if (error?.code !== "ER_DUP_FIELDNAME") {
      throw error;
    }
  }
};

const ensureMemberRequestColumns = async (connection) => {
  if (IS_POSTGRES) {
    await connection.execute(
      "ALTER TABLE prayer_requests ADD COLUMN IF NOT EXISTS whatsapp_number VARCHAR(50)",
    );
    await connection.execute(
      "ALTER TABLE counseling_requests ADD COLUMN IF NOT EXISTS whatsapp_number VARCHAR(50)",
    );
    return;
  }

  const alterStatements = [
    "ALTER TABLE prayer_requests ADD COLUMN whatsapp_number VARCHAR(50) NULL",
    "ALTER TABLE counseling_requests ADD COLUMN whatsapp_number VARCHAR(50) NULL",
  ];

  for (const statement of alterStatements) {
    try {
      await connection.execute(statement);
    } catch (error) {
      if (error?.code !== "ER_DUP_FIELDNAME") {
        throw error;
      }
    }
  }
};

const formatSettingsRows = (settings = []) => {
  const formattedSettings = {};

  settings.forEach((setting) => {
    let value = setting.setting_value;

    if (setting.setting_type === "json") {
      try {
        value = JSON.parse(value);
      } catch (error) {
        value = setting.setting_value;
      }
    } else if (setting.setting_type === "number") {
      value = Number(value);
    } else if (setting.setting_type === "boolean") {
      value = value === "true";
    }

    formattedSettings[setting.setting_key] = value;
  });

  return formattedSettings;
};

const getSettingsMap = async (keys = []) => {
  let query = "SELECT setting_key, setting_value, setting_type FROM settings";
  const params = [];

  if (Array.isArray(keys) && keys.length > 0) {
    query += ` WHERE setting_key IN (${keys.map(() => "?").join(", ")})`;
    params.push(...keys);
  }

  query += " ORDER BY setting_key";

  const [settings] = await pool.execute(query, params);
  return formatSettingsRows(settings);
};

const buildPublicSupportConfig = (settings = {}) => ({
  site_title: settings.site_title || "Spiritual Center",
  contact_email: settings.contact_email || "admin@spiritualcenter.com",
  contact_phone: settings.contact_phone || "+234 907 256 0420",
  whatsapp_number: settings.whatsapp_number || "+2349072560420",
  heading: settings.support_heading || "Support the Ministry",
  intro:
    settings.support_intro ||
    "Your support helps sustain biblical teaching, prayer care, counseling, outreach, and ministry media.",
  currency: settings.support_currency || "NGN",
  bank_name: settings.support_bank_name || "",
  account_name: settings.support_account_name || "",
  account_number: settings.support_account_number || "",
  payment_note:
    settings.support_payment_note ||
    "After sending your support, reach the ministry through WhatsApp or email with your transfer details so it can be confirmed quickly.",
  payment_link: settings.support_payment_link || "",
  support_email:
    settings.support_email ||
    settings.contact_email ||
    "admin@spiritualcenter.com",
  support_whatsapp:
    settings.support_whatsapp || settings.whatsapp_number || "+2349072560420",
});

const ensureDefaultAdminUser = async (connection) => {
  const upsertAdminUser = async ({ email, username, password }) => {
    const normalizedEmail = String(email).trim().toLowerCase();
    const normalizedUsername = String(username).trim().toLowerCase();
    const hashedPassword = await bcrypt.hash(password, 12);

    const [emailMatches] = await connection.execute(
      "SELECT id FROM users WHERE LOWER(email) = ? LIMIT 1",
      [normalizedEmail],
    );

    if (emailMatches.length > 0) {
      await connection.execute(
        `
          UPDATE users
          SET username = ?,
              password = ?,
              role = ?,
              is_approved = ?,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `,
        [username, hashedPassword, "admin", true, emailMatches[0].id],
      );
      return;
    }

    const [usernameMatches] = await connection.execute(
      "SELECT id FROM users WHERE LOWER(username) = ? LIMIT 1",
      [normalizedUsername],
    );

    if (usernameMatches.length > 0) {
      await connection.execute(
        `
          UPDATE users
          SET email = ?,
              password = ?,
              role = ?,
              is_approved = ?,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `,
        [email, hashedPassword, "admin", true, usernameMatches[0].id],
      );
      return;
    }

    await connection.execute(
      "INSERT INTO users (username, email, password, role, is_approved) VALUES (?, ?, ?, ?, ?)",
      [username, email, hashedPassword, "admin", true],
    );
  };

  const adminEmail =
    process.env.DEFAULT_ADMIN_EMAIL || "Wisdomadiele57@gmail.com";
  const adminRawPassword = process.env.DEFAULT_ADMIN_PASSWORD || "admin123";
  const adminUsername = process.env.DEFAULT_ADMIN_USERNAME || "admin";

  await upsertAdminUser({
    email: adminEmail,
    username: adminUsername,
    password: adminRawPassword,
  });

  const secondaryAdminEmail =
    process.env.SECONDARY_ADMIN_EMAIL || "admin@spiritualcenter.com";
  const secondaryAdminPassword =
    process.env.SECONDARY_ADMIN_PASSWORD || "admin123";
  const secondaryAdminUsername =
    process.env.SECONDARY_ADMIN_USERNAME || "admin2";

  await upsertAdminUser({
    email: secondaryAdminEmail,
    username: secondaryAdminUsername,
    password: secondaryAdminPassword,
  });

  return {
    email: adminEmail,
    password: adminRawPassword,
  };
};

let devotionTablesEnsured = false;

const ensureDevotionTables = async () => {
  if (devotionTablesEnsured) {
    return;
  }

  const postgresStatements = [
    `
      CREATE TABLE IF NOT EXISTS devotion_posts (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255),
        devotion_text TEXT NOT NULL,
        author VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `,
    "CREATE INDEX IF NOT EXISTS idx_devotion_posts_created ON devotion_posts (created_at)",
    `
      CREATE TABLE IF NOT EXISTS comments (
        id SERIAL PRIMARY KEY,
        post_type VARCHAR(50) NOT NULL,
        post_id INTEGER NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        comment_text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `,
    "CREATE INDEX IF NOT EXISTS idx_comments_post ON comments (post_type, post_id)",
    "CREATE INDEX IF NOT EXISTS idx_comments_created ON comments (created_at)",
  ];

  const mysqlStatements = [
    `
      CREATE TABLE IF NOT EXISTS devotion_posts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255),
        devotion_text TEXT NOT NULL,
        author VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_created (created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
    `
      CREATE TABLE IF NOT EXISTS comments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        post_type VARCHAR(50) NOT NULL,
        post_id INT NOT NULL,
        user_id INT,
        comment_text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_post (post_type, post_id),
        INDEX idx_created (created_at),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `,
  ];

  const statements = IS_POSTGRES ? postgresStatements : mysqlStatements;

  for (const statement of statements) {
    await pool.execute(statement);
  }

  devotionTablesEnsured = true;
};

const initializePostgresDatabase = async () => {
  let connection;

  try {
    connection = await pool.getConnection();
    await connection.execute("BEGIN");

    for (const statement of postgresSchemaStatements) {
      await connection.execute(statement);
    }

    await ensureUserAuthColumns(connection);
    await ensureMaterialColumns(connection);
    await ensureDonationColumns(connection);
    await ensureMemberRequestColumns(connection);

    await ensureDefaultAdminUser(connection);

    for (const [key, value, type] of DEFAULT_SETTINGS) {
      await connection.execute(INSERT_DEFAULT_SETTING_SQL, [key, value, type]);
    }

    await connection.execute("COMMIT");
    console.log("Database initialized successfully (postgres)");
    return true;
  } catch (error) {
    if (connection) {
      try {
        await connection.execute("ROLLBACK");
      } catch (rollbackError) {
        console.error("Rollback failed:", rollbackError.message);
      }
    }

    console.error("Database initialization failed:", error.message);
    return false;
  } finally {
    if (connection && typeof connection.release === "function") {
      connection.release();
    }
  }
};

const initializeDatabase = async () => {
  if (IS_POSTGRES) {
    return initializePostgresDatabase();
  }

  try {
    const connection = await pool.getConnection();

    // Users table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) NOT NULL UNIQUE,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        reset_password_token VARCHAR(128) NULL,
        reset_password_expires TIMESTAMP NULL,
        role ENUM('user', 'admin') DEFAULT 'user',
        is_approved BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_email (email),
        INDEX idx_role (role)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await ensureUserAuthColumns(connection);

    // Materials table (simplified - using this as main content table)
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS materials (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(500) NOT NULL,
        description TEXT,
        category VARCHAR(100),
        type ENUM('document', 'image', 'video', 'audio', 'writeup') NOT NULL,
        file_url VARCHAR(1000),
        youtube_url VARCHAR(1000),
        file_name VARCHAR(255),
        file_size INT,
        is_public BOOLEAN DEFAULT TRUE,
        uploader_id INT,
        views INT DEFAULT 0,
        downloads INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (uploader_id) REFERENCES users(id) ON DELETE SET NULL,
        INDEX idx_category (category),
        INDEX idx_type (type),
        INDEX idx_public (is_public),
        FULLTEXT idx_search (title, description)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await ensureMaterialColumns(connection);

    // Prayer requests table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS prayer_requests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255),
        whatsapp_number VARCHAR(50),
        request TEXT NOT NULL,
        is_anonymous BOOLEAN DEFAULT FALSE,
        status ENUM('pending', 'read', 'responded') DEFAULT 'pending',
        user_id INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        INDEX idx_status (status),
        INDEX idx_created (created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    // Counseling requests table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS counseling_requests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        counseling_type VARCHAR(100) NOT NULL,
        whatsapp_number VARCHAR(50),
        description TEXT NOT NULL,
        preferred_availability VARCHAR(255),
        status ENUM('pending', 'scheduled', 'completed', 'cancelled') DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_status (status),
        INDEX idx_user_id (user_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    // Daily promises table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS daily_promises (
        id INT AUTO_INCREMENT PRIMARY KEY,
        promise_text TEXT NOT NULL,
        author VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_created (created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    // Devotion posts table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS devotion_posts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255),
        devotion_text TEXT NOT NULL,
        author VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_created (created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    // Comments table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS comments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        post_type VARCHAR(50) NOT NULL,
        post_id INT NOT NULL,
        user_id INT,
        comment_text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_post (post_type, post_id),
        INDEX idx_created (created_at),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    // Donations table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS donations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        amount DECIMAL(10,2) NOT NULL,
        currency VARCHAR(10) DEFAULT 'USD',
        donor_name VARCHAR(255) NOT NULL,
        donor_email VARCHAR(255) NOT NULL,
        message TEXT,
        payment_method VARCHAR(50) NOT NULL,
        transaction_id VARCHAR(100) UNIQUE,
        status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_status (status),
        INDEX idx_email (donor_email)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await ensureDonationColumns(connection);
    await ensureMemberRequestColumns(connection);

    // Analytics table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS analytics (
        id INT AUTO_INCREMENT PRIMARY KEY,
        event_type VARCHAR(50) NOT NULL,
        event_data JSON,
        user_id INT,
        user_agent TEXT,
        ip_address VARCHAR(45),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_event_type (event_type),
        INDEX idx_created (created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    // Settings table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS settings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        setting_key VARCHAR(100) NOT NULL UNIQUE,
        setting_value TEXT,
        setting_type ENUM('string', 'number', 'boolean', 'json') DEFAULT 'string',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_key (setting_key)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    // Create default admin user
    await ensureDefaultAdminUser(connection);

    // Insert default settings without overwriting admin changes
    for (const [key, value, type] of DEFAULT_SETTINGS) {
      await connection.execute(INSERT_DEFAULT_SETTING_SQL, [key, value, type]);
    }

    connection.release();
    console.log("✅ Database initialized successfully");
    return true;
  } catch (error) {
    console.error("❌ Database initialization failed:", error.message);
    return false;
  }
};

// ==================== ADMIN DASHBOARD ENDPOINTS ====================

// Get comprehensive dashboard stats
app.get("/api/admin/stats", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    // Get all stats in parallel
    const [
      [{ total_users } = { total_users: 0 }],
      [{ total_materials } = { total_materials: 0 }],
      [{ total_prayers } = { total_prayers: 0 }],
      [{ pending_prayers } = { pending_prayers: 0 }],
      [{ pending_counseling } = { pending_counseling: 0 }],
      [
        { total_donations, total_amount } = {
          total_donations: 0,
          total_amount: 0,
        },
      ],
      [{ recent_uploads } = { recent_uploads: 0 }],
      [{ active_users } = { active_users: 0 }],
    ] = await Promise.all([
      pool
        .execute("SELECT COUNT(*) as total_users FROM users")
        .then((r) => r[0]),
      pool
        .execute("SELECT COUNT(*) as total_materials FROM materials")
        .then((r) => r[0]),
      pool
        .execute("SELECT COUNT(*) as total_prayers FROM prayer_requests")
        .then((r) => r[0]),
      pool
        .execute(
          "SELECT COUNT(*) as pending_prayers FROM prayer_requests WHERE status = 'pending'",
        )
        .then((r) => r[0]),
      pool
        .execute(
          "SELECT COUNT(*) as pending_counseling FROM counseling_requests WHERE status = 'pending'",
        )
        .then((r) => r[0]),
      pool
        .execute(
          "SELECT COUNT(*) as total_donations, COALESCE(SUM(amount), 0) as total_amount FROM donations WHERE status = 'completed'",
        )
        .then((r) => r[0]),
      pool
        .execute(
          "SELECT COUNT(*) as recent_uploads FROM materials WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)",
        )
        .then((r) => r[0]),
      pool
        .execute(
          "SELECT COUNT(DISTINCT user_id) as active_users FROM analytics WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY) AND user_id IS NOT NULL",
        )
        .then((r) => r[0]),
    ]);

    // Get storage used
    const [storageResult] = await pool.execute(
      "SELECT COALESCE(SUM(file_size), 0) as total_size FROM materials WHERE file_size IS NOT NULL",
    );
    const storage_used =
      Math.round(
        ((storageResult[0]?.total_size || 0) / (1024 * 1024 * 1024)) * 100,
      ) / 100; // GB

    // Get recent materials
    const [recentMaterials] = await pool.execute(`
      SELECT m.id, m.title, m.type, m.created_at, u.username as uploader
      FROM materials m
      LEFT JOIN users u ON m.uploader_id = u.id
      ORDER BY m.created_at DESC
      LIMIT 5
    `);

    // Get top materials by views
    const [topMaterials] = await pool.execute(`
      SELECT id, title, views, downloads
      FROM materials
      ORDER BY views DESC
      LIMIT 5
    `);

    res.json({
      success: true,
      stats: {
        total_users,
        total_materials,
        total_prayers,
        pending_prayers,
        pending_counseling,
        pending_requests:
          Number(pending_prayers || 0) + Number(pending_counseling || 0),
        total_donations,
        total_amount: parseFloat(total_amount),
        recent_uploads,
        active_users,
        storage_used: `${storage_used} GB`,
        engagement_rate:
          total_users > 0 ? Math.round((active_users / total_users) * 100) : 0,
      },
      recent_materials: recentMaterials,
      top_materials: topMaterials,
      updated_at: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Dashboard stats error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch dashboard stats",
      details: error.message,
    });
  }
});

// ==================== MATERIALS ENDPOINTS ====================

// Upload material
app.post(
  "/api/materials/upload",
  authenticateToken,
  upload.single("file"),
  async (req, res) => {
    let uploadedSupabaseObjectPath = null;

    try {
      if (req.user.role !== "admin") {
        return res.status(403).json({ error: "Admin access required" });
      }

      const {
        title,
        description,
        category,
        type,
        is_public = "true",
        youtube_url = "",
      } = req.body;
      const userId = req.user.userId;
      const normalizedYoutubeUrl = normalizeOptionalUrl(youtube_url);

      // Validation
      if (!title || !description || !category || !type) {
        if (req.file) {
          safeUnlink(req.file.path);
        }
        return res.status(400).json({
          success: false,
          error: "All fields are required",
        });
      }

      if (!req.file && type !== "writeup") {
        return res.status(400).json({
          success: false,
          error: "File is required for this material type",
        });
      }

      if (!isValidYouTubeUrl(normalizedYoutubeUrl)) {
        if (req.file) {
          safeUnlink(req.file.path);
        }
        return res.status(400).json({
          success: false,
          error: "Please provide a valid YouTube link",
        });
      }

      if (
        req.file &&
        REQUIRE_PERSISTENT_STORAGE &&
        !isSupabaseStorageConfigured()
      ) {
        safeUnlink(req.file.path);
        return res.status(500).json({
          success: false,
          error:
            "Persistent storage is not configured. Set SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, and SUPABASE_STORAGE_BUCKET, or set REQUIRE_PERSISTENT_STORAGE=false to allow local /uploads storage.",
        });
      }

      let fileUrl = null;
      let fileName = null;
      let fileSize = null;

      if (req.file) {
        fileName = req.file.originalname;
        fileSize = req.file.size;

        const uploadedToSupabase = await uploadFileToSupabaseStorage(
          req.file,
          type,
        );

        if (uploadedToSupabase) {
          uploadedSupabaseObjectPath = uploadedToSupabase.objectPath;
          fileUrl = uploadedToSupabase.publicUrl;
          safeUnlink(req.file.path);
        } else {
          fileUrl = `/uploads/${req.file.filename}`;
        }
      }

      // Insert material
      const [result] = await pool.execute(
        `
      INSERT INTO materials 
        (title, description, category, type, file_url, youtube_url, file_name, file_size, is_public, uploader_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
        [
          title,
          description,
          category,
          type,
          fileUrl,
          normalizedYoutubeUrl,
          fileName,
          fileSize,
          is_public === "true",
          userId,
        ],
      );

      // Log analytics
      await pool.execute(
        "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
        [
          "material_upload",
          JSON.stringify({ material_id: result.insertId, title, type }),
          userId,
        ],
      );

      res.status(201).json({
        success: true,
        message: "Material uploaded successfully",
        material: {
          id: result.insertId,
          title,
          category,
          type,
          file_url: fileUrl,
          youtube_url: resolveMaterialYouTubeUrl({
            title,
            category,
            type,
            youtube_url: normalizedYoutubeUrl,
          }),
          created_at: new Date().toISOString(),
        },
      });
    } catch (error) {
      console.error("Material upload error:", error);
      if (uploadedSupabaseObjectPath) {
        try {
          await deleteSupabaseObjectByPath(uploadedSupabaseObjectPath);
        } catch (rollbackError) {
          console.error(
            "Failed to rollback Supabase storage object:",
            rollbackError,
          );
        }
      }
      if (req.file?.path) {
        safeUnlink(req.file.path);
      }
      const isPayloadTooLarge = error?.code === "PAYLOAD_TOO_LARGE";
      res.status(isPayloadTooLarge ? 413 : 500).json({
        success: false,
        error: isPayloadTooLarge ? error.message : "Failed to upload material",
        details: isPayloadTooLarge ? undefined : error.message,
      });
    }
  },
);

// Get materials (all materials are visible to visitors and admins)
app.get("/api/materials", authenticateOptionalToken, async (req, res) => {
  try {
    const {
      search = "",
      category = "",
      type = "",
      page = 1,
      limit = 20,
    } = req.query;
    const parsedPage = Math.max(parseInt(page, 10) || 1, 1);
    const parsedLimit = Math.min(Math.max(parseInt(limit, 10) || 20, 1), 100);
    const offset = (parsedPage - 1) * parsedLimit;
    const paginationClause = `LIMIT ${parsedLimit} OFFSET ${offset}`;
    const isAdminRequest = req.user?.role === "admin";

    const whereParts = [];
    const filterParams = [];
    if (search) {
      whereParts.push("(m.title LIKE ? OR m.description LIKE ?)");
      filterParams.push(`%${search}%`, `%${search}%`);
    }
    if (category) {
      whereParts.push("m.category = ?");
      filterParams.push(category);
    }
    if (type) {
      whereParts.push("m.type = ?");
      filterParams.push(type);
    }
    const whereClause = whereParts.length
      ? `WHERE ${whereParts.join(" AND ")}`
      : "";

    const countQuery = `
      SELECT COUNT(*) as total
      FROM materials m
      ${whereClause}
    `;
    const [countResult] = await pool.execute(countQuery, filterParams);
    const total = Number(countResult[0]?.total || 0);

    const selectQuery = isAdminRequest
      ? `
        SELECT
          m.id,
          m.title,
          m.description,
          m.category,
          m.type,
          m.file_url,
          m.youtube_url,
          m.file_name,
          m.file_size,
          m.views,
          m.downloads,
          m.is_public,
          m.uploader_id,
          m.created_at,
          m.updated_at,
          u.username as uploader_name,
          u.email as uploader_email
        FROM materials m
        LEFT JOIN users u ON m.uploader_id = u.id
        ${whereClause}
        ORDER BY m.created_at DESC
        ${paginationClause}
      `
      : `
        SELECT
          m.id,
          m.title,
          m.description,
          m.category,
          m.type,
          m.file_url,
          m.youtube_url,
          m.file_name,
          m.file_size,
          m.views,
          m.downloads,
          m.is_public,
          m.uploader_id,
          m.created_at,
          m.updated_at,
          u.username as uploader_name
        FROM materials m
        LEFT JOIN users u ON m.uploader_id = u.id
        ${whereClause}
        ORDER BY m.created_at DESC
        ${paginationClause}
      `;

    const [materials] = await pool.execute(selectQuery, filterParams);

    const normalizedMaterials = (materials || []).map((material) => {
      const isPublicValue =
        material?.is_public === true ||
        material?.is_public === 1 ||
        material?.is_public === "1" ||
        material?.is_public === "true";

      return {
        id: material.id,
        title: material.title || "Untitled",
        description: material.description || "",
        category: material.category || "uncategorized",
        type: material.type || "document",
        file_url: material.file_url || null,
        youtube_url: resolveMaterialYouTubeUrl(material),
        file_name: material.file_name || null,
        file_size: Number(material.file_size || 0),
        views: Number(material.views || 0),
        downloads: Number(material.downloads || 0),
        is_public: isPublicValue,
        uploader_id: material.uploader_id || null,
        uploader_name: material.uploader_name || "System",
        uploader_email: isAdminRequest
          ? material.uploader_email || null
          : undefined,
        created_at: material.created_at,
        updated_at: material.updated_at,
      };
    });

    return res.json({
      success: true,
      access: isAdminRequest ? "admin" : "public",
      materials: normalizedMaterials,
      pagination: {
        page: parsedPage,
        limit: parsedLimit,
        total,
        pages: Math.ceil(total / parsedLimit),
      },
    });
  } catch (error) {
    console.error("Get materials error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch materials",
      details: error.message,
    });
  }
});

// Get single material
app.get("/api/materials/:id", authenticateOptionalToken, async (req, res) => {
  try {
    const materialId = req.params.id;
    const isAdminRequest = req.user?.role === "admin";
    const selectQuery = isAdminRequest
      ? `
      SELECT
        m.id,
        m.title,
        m.description,
        m.category,
        m.type,
        m.file_url,
        m.youtube_url,
        m.file_name,
        m.file_size,
        m.views,
        m.downloads,
        m.is_public,
        m.uploader_id,
        m.created_at,
        m.updated_at,
        u.username as uploader_name,
        u.email as uploader_email
      FROM materials m
      LEFT JOIN users u ON m.uploader_id = u.id
      WHERE m.id = ?
    `
      : `
      SELECT
        m.id,
        m.title,
        m.description,
        m.category,
        m.type,
        m.file_url,
        m.youtube_url,
        m.file_name,
        m.file_size,
        m.views,
        m.downloads,
        m.is_public,
        m.uploader_id,
        m.created_at,
        m.updated_at,
        u.username as uploader_name
      FROM materials m
      LEFT JOIN users u ON m.uploader_id = u.id
      WHERE m.id = ?
    `;

    const [materials] = await pool.execute(selectQuery, [materialId]);

    if (materials.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Material not found",
      });
    }

    // Increment view count
    await pool.execute("UPDATE materials SET views = views + 1 WHERE id = ?", [
      materialId,
    ]);

    const material = materials[0];
    const isPublicValue =
      material?.is_public === true ||
      material?.is_public === 1 ||
      material?.is_public === "1" ||
      material?.is_public === "true";

    res.json({
      success: true,
      material: {
        id: material.id,
        title: material.title || "Untitled",
        description: material.description || "",
        category: material.category || "uncategorized",
        type: material.type || "document",
        file_url: material.file_url || null,
        youtube_url: resolveMaterialYouTubeUrl(material),
        file_name: material.file_name || null,
        file_size: Number(material.file_size || 0),
        views: Number(material.views || 0),
        downloads: Number(material.downloads || 0),
        is_public: isPublicValue,
        uploader_id: material.uploader_id || null,
        uploader_name: material.uploader_name || "System",
        uploader_email: isAdminRequest
          ? material.uploader_email || null
          : undefined,
        created_at: material.created_at,
        updated_at: material.updated_at,
      },
    });
  } catch (error) {
    console.error("Get material error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch material",
      details: error.message,
    });
  }
});

// Update material
app.put("/api/materials/:id", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const materialId = req.params.id;
    const { title, description, category, type, is_public, youtube_url } =
      req.body;
    const normalizedYoutubeUrl = normalizeOptionalUrl(youtube_url);

    if (!isValidYouTubeUrl(normalizedYoutubeUrl)) {
      return res.status(400).json({
        success: false,
        error: "Please provide a valid YouTube link",
      });
    }

    // Check if material exists
    const [existing] = await pool.execute(
      "SELECT id FROM materials WHERE id = ?",
      [materialId],
    );

    if (existing.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Material not found",
      });
    }

    // Update material
    await pool.execute(
      `
      UPDATE materials 
      SET title = ?, description = ?, category = ?, type = ?, is_public = ?, youtube_url = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `,
      [
        title,
        description,
        category,
        type,
        is_public === "true",
        normalizedYoutubeUrl,
        materialId,
      ],
    );

    // Log analytics
    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
      [
        "material_update",
        JSON.stringify({ material_id: materialId }),
        req.user.userId,
      ],
    );

    res.json({
      success: true,
      message: "Material updated successfully",
    });
  } catch (error) {
    console.error("Update material error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to update material",
      details: error.message,
    });
  }
});

// Delete material
app.delete("/api/materials/:id", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const materialId = req.params.id;

    // Get material details
    const [materials] = await pool.execute(
      "SELECT file_url FROM materials WHERE id = ?",
      [materialId],
    );

    if (materials.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Material not found",
      });
    }

    // Delete file if exists
    if (materials[0].file_url) {
      await removeStoredMaterialFile(materials[0].file_url);
    }

    // Delete from database
    await pool.execute("DELETE FROM materials WHERE id = ?", [materialId]);

    // Log analytics
    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
      [
        "material_delete",
        JSON.stringify({ material_id: materialId }),
        req.user.userId,
      ],
    );

    res.json({
      success: true,
      message: "Material deleted successfully",
    });
  } catch (error) {
    console.error("Delete material error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to delete material",
      details: error.message,
    });
  }
});

// ==================== ANALYTICS ENDPOINTS ====================

// Get comprehensive analytics
app.get("/api/analytics", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { period = "7d" } = req.query;
    let dateFilter = "";

    switch (period) {
      case "1d":
        dateFilter = "AND created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)";
        break;
      case "7d":
        dateFilter = "AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)";
        break;
      case "30d":
        dateFilter = "AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)";
        break;
      case "90d":
        dateFilter = "AND created_at >= DATE_SUB(NOW(), INTERVAL 90 DAY)";
        break;
    }

    // Get user growth
    const [userGrowth] = await pool.execute(`
      SELECT 
        DATE(created_at) as date,
        COUNT(*) as new_users
      FROM users 
      WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
      GROUP BY DATE(created_at)
      ORDER BY date
    `);

    // Get material growth
    const [materialGrowth] = await pool.execute(`
      SELECT 
        DATE(created_at) as date,
        COUNT(*) as new_materials,
        SUM(CASE WHEN type = 'video' THEN 1 ELSE 0 END) as videos,
        SUM(CASE WHEN type = 'document' THEN 1 ELSE 0 END) as documents,
        SUM(CASE WHEN type = 'image' THEN 1 ELSE 0 END) as images,
        SUM(CASE WHEN type = 'audio' THEN 1 ELSE 0 END) as audio
      FROM materials 
      WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
      GROUP BY DATE(created_at)
      ORDER BY date
    `);

    // Get top materials by views
    const [topMaterials] = await pool.execute(`
      SELECT 
        id, title, type, views, downloads,
        ROUND(downloads * 100.0 / NULLIF(views, 0), 2) as conversion_rate
      FROM materials
      ORDER BY views DESC
      LIMIT 10
    `);

    // Get activity by hour
    const [activityByHour] = await pool.execute(`
      SELECT 
        HOUR(created_at) as hour,
        COUNT(*) as activity_count
      FROM analytics
      WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
      GROUP BY HOUR(created_at)
      ORDER BY hour
    `);

    // Get event breakdown
    const [eventBreakdown] = await pool.execute(`
      SELECT 
        event_type,
        COUNT(*) as count
      FROM analytics
      WHERE 1=1 ${dateFilter}
      GROUP BY event_type
      ORDER BY count DESC
    `);

    // Get real-time stats (last 24 hours)
    const [realtimeStats] = await pool.execute(`
      SELECT 
        COUNT(DISTINCT user_id) as active_users_today,
        COUNT(CASE WHEN event_type = 'material_view' THEN 1 END) as views_today,
        COUNT(CASE WHEN event_type = 'material_download' THEN 1 END) as downloads_today,
        COUNT(CASE WHEN event_type = 'login' THEN 1 END) as logins_today
      FROM analytics
      WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)
    `);

    res.json({
      success: true,
      analytics: {
        user_growth: userGrowth,
        material_growth: materialGrowth,
        top_materials: topMaterials,
        activity_by_hour: activityByHour,
        event_breakdown: eventBreakdown,
        realtime: realtimeStats[0] || {},
      },
      period,
      generated_at: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Analytics error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch analytics",
      details: error.message,
    });
  }
});

// Record analytics event
app.post("/api/analytics/event", async (req, res) => {
  try {
    const { event_type, event_data, user_id } = req.body;
    const userAgent = req.headers["user-agent"];
    const ip = req.ip || req.connection.remoteAddress;

    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id, user_agent, ip_address) VALUES (?, ?, ?, ?, ?)",
      [event_type, JSON.stringify(event_data), user_id, userAgent, ip],
    );

    res.json({ success: true });
  } catch (error) {
    console.error("Analytics event error:", error);
    res.status(500).json({ success: false, error: "Failed to record event" });
  }
});

// ==================== SETTINGS ENDPOINTS ====================

// Get all settings
app.get("/api/settings", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const [settings] = await pool.execute(
      "SELECT setting_key, setting_value, setting_type FROM settings ORDER BY setting_key",
    );

    res.json({
      success: true,
      settings: formatSettingsRows(settings),
    });
  } catch (error) {
    console.error("Get settings error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch settings",
      details: error.message,
    });
  }
});

// Update settings
app.put("/api/settings", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const settings = req.body;
    const updates = [];

    for (const [key, value] of Object.entries(settings)) {
      let settingType = "string";
      let settingValue = value;

      if (typeof value === "boolean") {
        settingType = "boolean";
        settingValue = value.toString();
      } else if (typeof value === "number") {
        settingType = "number";
        settingValue = value.toString();
      } else if (typeof value === "object") {
        settingType = "json";
        settingValue = JSON.stringify(value);
      }

      updates.push(
        pool.execute(UPSERT_SETTING_SQL, [key, settingValue, settingType]),
      );
    }

    await Promise.all(updates);

    // Log settings change
    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
      [
        "settings_update",
        JSON.stringify({ settings: Object.keys(settings) }),
        req.user.userId,
      ],
    );

    res.json({
      success: true,
      message: "Settings updated successfully",
    });
  } catch (error) {
    console.error("Update settings error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to update settings",
      details: error.message,
    });
  }
});

// ==================== NOTIFICATIONS ENDPOINTS ====================

// Get notifications
app.get("/api/notifications", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { unread = false } = req.query;

    let query = `
      SELECT 
        n.*,
        u.username as from_user,
        u.email as from_email
      FROM (
        -- Prayer request notifications
        SELECT 
          id as source_id,
          'prayer_request' as type,
          CONCAT('New prayer request from ', COALESCE(name, 'Anonymous')) as title,
          SUBSTRING(request, 1, 100) as message,
          created_at,
          FALSE as is_read,
          user_id as from_user_id
        FROM prayer_requests
        WHERE status = 'pending'
        
        UNION ALL
        
        -- User registration notifications
        SELECT 
          id as source_id,
          'user_registration' as type,
          CONCAT('New user registration: ', username) as title,
          email as message,
          created_at,
          FALSE as is_read,
          id as from_user_id
        FROM users
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY) AND role = 'user'
        
        UNION ALL
        
        -- System notifications
        SELECT 
          id as source_id,
          'system' as type,
          'System Update' as title,
          'Your system is running smoothly' as message,
          NOW() as created_at,
          TRUE as is_read,
          NULL as from_user_id
        FROM (SELECT 1 as id) as dummy
        LIMIT 1
      ) as n
      LEFT JOIN users u ON n.from_user_id = u.id
    `;

    if (unread === "true") {
      query += " WHERE n.is_read = FALSE";
    }

    query += " ORDER BY n.created_at DESC LIMIT 50";

    const [notifications] = await pool.execute(query);

    // Count unread notifications
    const [unreadCountResult] = await pool.execute(`
      SELECT COUNT(*) as count FROM prayer_requests WHERE status = 'pending'
    `);
    const unread_count = unreadCountResult[0]?.count || 0;

    res.json({
      success: true,
      notifications,
      unread_count,
      total: notifications.length,
    });
  } catch (error) {
    console.error("Get notifications error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch notifications",
      details: error.message,
    });
  }
});

// Mark notification as read
app.put("/api/notifications/:id/read", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const notificationId = req.params.id;
    const { type } = req.body;

    if (type === "prayer_request") {
      await pool.execute(
        "UPDATE prayer_requests SET status = 'read' WHERE id = ?",
        [notificationId],
      );
    }

    res.json({
      success: true,
      message: "Notification marked as read",
    });
  } catch (error) {
    console.error("Mark notification read error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to mark notification as read",
      details: error.message,
    });
  }
});

// Clear all notifications
app.delete("/api/notifications", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    // Mark all prayer requests as read
    await pool.execute(
      "UPDATE prayer_requests SET status = 'read' WHERE status = 'pending'",
    );

    res.json({
      success: true,
      message: "All notifications cleared",
    });
  } catch (error) {
    console.error("Clear notifications error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to clear notifications",
      details: error.message,
    });
  }
});

// ==================== AUTH ENDPOINTS ====================

app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;
    const normalizedEmail = normalizeEmail(email);
    const normalizedUsername = normalizeUsername(username);

    if (!normalizedUsername || !normalizedEmail || !password) {
      return res.status(400).json({
        success: false,
        error: "Username, email, and password are required",
      });
    }

    if (normalizedUsername.length < 3 || normalizedUsername.length > 100) {
      return res.status(400).json({
        success: false,
        error: "Username must be between 3 and 100 characters",
      });
    }

    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        error: "Please provide a valid email address",
      });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({
        success: false,
        error: "Password must be at least 8 characters long",
      });
    }

    if (
      typeof confirmPassword === "string" &&
      confirmPassword.length > 0 &&
      password !== confirmPassword
    ) {
      return res.status(400).json({
        success: false,
        error: "Password confirmation does not match",
      });
    }

    const [existingUsers] = await pool.execute(
      "SELECT id FROM users WHERE email = ? OR username = ? LIMIT 1",
      [normalizedEmail, normalizedUsername],
    );

    if (existingUsers.length > 0) {
      return res.status(409).json({
        success: false,
        error: "An account already exists with that email or username",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const [insertResult] = await pool.execute(
      "INSERT INTO users (username, email, password, role, is_approved) VALUES (?, ?, ?, ?, ?)",
      [normalizedUsername, normalizedEmail, passwordHash, "user", true],
    );

    let userId = insertResult?.insertId || null;
    if (!userId) {
      const [createdUsers] = await pool.execute(
        "SELECT id FROM users WHERE email = ? LIMIT 1",
        [normalizedEmail],
      );
      userId = createdUsers[0]?.id || null;
    }

    const user = {
      id: userId,
      username: normalizedUsername,
      email: normalizedEmail,
      role: "user",
      is_approved: true,
    };

    const token = signAuthToken(user);

    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
      ["register", JSON.stringify({ method: "email_password" }), user.id],
    );

    res.status(201).json({
      success: true,
      message: "Registration successful",
      token,
      user,
    });
  } catch (error) {
    if (error?.code === "ER_DUP_ENTRY" || error?.code === "23505") {
      return res.status(409).json({
        success: false,
        error: "An account already exists with that email or username",
      });
    }

    console.error("Register error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to create account",
      details: error.message,
    });
  }
});

app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const normalizedEmail = normalizeEmail(req.body?.email);

    if (!normalizedEmail || !isValidEmail(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        error: "Please provide a valid email address",
      });
    }

    const [users] = await pool.execute(
      "SELECT id, email FROM users WHERE email = ? LIMIT 1",
      [normalizedEmail],
    );

    const genericResponse = {
      success: true,
      message:
        "If the account exists, password recovery instructions have been generated.",
    };

    if (users.length === 0) {
      return res.json(genericResponse);
    }

    const user = users[0];
    const { rawToken, hashedToken, expiresAt } = createRecoveryToken();

    await pool.execute(
      "UPDATE users SET reset_password_token = ?, reset_password_expires = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      [hashedToken, expiresAt, user.id],
    );

    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
      [
        "password_reset_requested",
        JSON.stringify({ channel: "self_service", email: normalizedEmail }),
        user.id,
      ],
    );

    if (ALLOW_PLAINTEXT_RESET_TOKEN) {
      return res.json({
        ...genericResponse,
        recovery_code: rawToken,
        expires_at: expiresAt.toISOString(),
      });
    }

    return res.json(genericResponse);
  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to process password recovery request",
      details: error.message,
    });
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { email, recoveryCode, newPassword, confirmPassword } = req.body;
    const normalizedEmail = normalizeEmail(email);

    if (!normalizedEmail || !isValidEmail(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        error: "Please provide a valid email address",
      });
    }

    if (!recoveryCode) {
      return res.status(400).json({
        success: false,
        error: "Recovery code is required",
      });
    }

    if (!isStrongPassword(newPassword)) {
      return res.status(400).json({
        success: false,
        error: "New password must be at least 8 characters long",
      });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        error: "Password confirmation does not match",
      });
    }

    const [users] = await pool.execute(
      "SELECT id, username, email, role, is_approved, reset_password_token, reset_password_expires FROM users WHERE email = ? LIMIT 1",
      [normalizedEmail],
    );

    if (users.length === 0) {
      return res.status(400).json({
        success: false,
        error: "Invalid or expired recovery code",
      });
    }

    const user = users[0];
    const storedToken = user.reset_password_token;
    const storedExpiry = user.reset_password_expires;
    const hashedProvidedToken = hashRecoveryToken(recoveryCode);

    if (!storedToken || !storedExpiry) {
      return res.status(400).json({
        success: false,
        error: "Invalid or expired recovery code",
      });
    }

    const expiryDate = new Date(storedExpiry);
    const isExpired =
      Number.isNaN(expiryDate.getTime()) || expiryDate.getTime() < Date.now();

    if (isExpired || storedToken !== hashedProvidedToken) {
      return res.status(400).json({
        success: false,
        error: "Invalid or expired recovery code",
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    await pool.execute(
      "UPDATE users SET password = ?, reset_password_token = NULL, reset_password_expires = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      [hashedPassword, user.id],
    );

    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
      ["password_reset", JSON.stringify({ method: "recovery_code" }), user.id],
    );

    const authUser = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      is_approved: user.is_approved,
    };
    const token = signAuthToken(authUser);

    res.json({
      success: true,
      message: "Password reset successful",
      token,
      user: authUser,
    });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to reset password",
      details: error.message,
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, username, identifier, password } = req.body;
    const rawIdentifier =
      typeof email === "string" && email.trim().length > 0
        ? email
        : typeof username === "string" && username.trim().length > 0
          ? username
          : identifier;
    const normalizedIdentifier = String(rawIdentifier || "")
      .trim()
      .toLowerCase();

    if (!normalizedIdentifier || !password) {
      return res.status(400).json({
        error: "Email/username and password are required",
      });
    }

    const isEmailIdentifier = normalizedIdentifier.includes("@");
    const loginQuery = isEmailIdentifier
      ? "SELECT * FROM users WHERE LOWER(email) = ? LIMIT 1"
      : "SELECT * FROM users WHERE LOWER(username) = ? LIMIT 1";

    const [users] = await pool.execute(loginQuery, [normalizedIdentifier]);

    if (users.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = users[0];

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Check if user is approved
    if (!user.is_approved && user.role !== "admin") {
      return res
        .status(401)
        .json({ error: "Your account is pending admin approval" });
    }

    // Generate JWT token
    const token = signAuthToken(user);

    // Log login event
    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
      ["login", JSON.stringify({ method: "email" }), user.id],
    );

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        is_approved: user.is_approved,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
      details: error.message,
    });
  }
});

// Validate token
app.get("/api/auth/validate", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const [users] = await pool.execute(
      "SELECT id, username, email, role, is_approved FROM users WHERE id = ?",
      [userId],
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    res.json({
      success: true,
      user: users[0],
    });
  } catch (error) {
    console.error("Validate token error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to validate token",
      details: error.message,
    });
  }
});

// ==================== USERS ENDPOINTS ====================

app.get("/api/users", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const {
      search = "",
      role = "",
      status = "",
      page = 1,
      limit = 20,
    } = req.query;
    const parsedPage = Math.max(Number.parseInt(page, 10) || 1, 1);
    const parsedLimit = Math.min(
      Math.max(Number.parseInt(limit, 10) || 20, 1),
      200,
    );
    const offset = (parsedPage - 1) * parsedLimit;

    let query = `
      SELECT 
        id, username, email, role, is_approved,
        DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at,
        DATE_FORMAT(updated_at, '%Y-%m-%d %H:%i:%s') as updated_at
      FROM users
      WHERE 1=1
    `;
    const params = [];

    if (search) {
      query += ` AND (username LIKE ? OR email LIKE ?)`;
      params.push(`%${search}%`, `%${search}%`);
    }

    if (role) {
      query += ` AND role = ?`;
      params.push(role);
    }

    if (status === "approved") {
      query += ` AND is_approved = TRUE`;
    } else if (status === "pending") {
      query += ` AND is_approved = FALSE`;
    }

    query += ` ORDER BY created_at DESC LIMIT ${parsedLimit} OFFSET ${offset}`;

    const [users] = await pool.execute(query, params);

    // Get total count
    const [countResult] = await pool.execute(
      query
        .split("ORDER BY")[0]
        .replace(
          "SELECT id, username, email, role, is_approved, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at, DATE_FORMAT(updated_at, '%Y-%m-%d %H:%i:%s') as updated_at",
          "SELECT COUNT(*) as total",
        ),
      params,
    );
    const total = countResult[0]?.total || 0;

    res.json({
      success: true,
      users,
      pagination: {
        page: parsedPage,
        limit: parsedLimit,
        total,
        pages: Math.ceil(total / parsedLimit),
      },
    });
  } catch (error) {
    console.error("Get users error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch users",
      details: error.message,
    });
  }
});

app.post("/api/users", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const normalizedUsername = normalizeUsername(req.body?.username);
    const normalizedEmail = normalizeEmail(req.body?.email);
    const password = String(req.body?.password || "");
    const role = String(req.body?.role || "user")
      .trim()
      .toLowerCase();
    const isApproved = parseBoolean(
      req.body?.is_approved ?? req.body?.isApproved,
      true,
    );

    if (!normalizedUsername || !normalizedEmail || !password) {
      return res.status(400).json({
        success: false,
        error: "Username, email, and password are required",
      });
    }

    if (normalizedUsername.length < 3 || normalizedUsername.length > 100) {
      return res.status(400).json({
        success: false,
        error: "Username must be between 3 and 100 characters",
      });
    }

    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        error: "Please provide a valid email address",
      });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({
        success: false,
        error: "Password must be at least 8 characters long",
      });
    }

    if (!["user", "admin"].includes(role)) {
      return res.status(400).json({
        success: false,
        error: 'Role must be either "user" or "admin"',
      });
    }

    const [existingUsers] = await pool.execute(
      "SELECT id FROM users WHERE email = ? OR username = ? LIMIT 1",
      [normalizedEmail, normalizedUsername],
    );

    if (existingUsers.length > 0) {
      return res.status(409).json({
        success: false,
        error: "A user already exists with that email or username",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const [insertResult] = await pool.execute(
      "INSERT INTO users (username, email, password, role, is_approved) VALUES (?, ?, ?, ?, ?)",
      [normalizedUsername, normalizedEmail, passwordHash, role, isApproved],
    );

    let createdUserId = insertResult?.insertId || null;
    if (!createdUserId) {
      const [createdRows] = await pool.execute(
        "SELECT id FROM users WHERE email = ? LIMIT 1",
        [normalizedEmail],
      );
      createdUserId = createdRows[0]?.id || null;
    }

    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
      [
        "user_create",
        JSON.stringify({
          created_user_id: createdUserId,
          role,
          is_approved: isApproved,
        }),
        req.user.userId,
      ],
    );

    res.status(201).json({
      success: true,
      message: "User created successfully",
      user: {
        id: createdUserId,
        username: normalizedUsername,
        email: normalizedEmail,
        role,
        is_approved: isApproved,
      },
    });
  } catch (error) {
    if (error?.code === "ER_DUP_ENTRY" || error?.code === "23505") {
      return res.status(409).json({
        success: false,
        error: "A user already exists with that email or username",
      });
    }

    console.error("Create user error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to create user",
      details: error.message,
    });
  }
});

app.put("/api/users/:id/approve", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const targetUserId = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
      return res.status(400).json({
        success: false,
        error: "Invalid user id",
      });
    }

    const [users] = await pool.execute(
      "SELECT id, is_approved FROM users WHERE id = ? LIMIT 1",
      [targetUserId],
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    if (users[0].is_approved) {
      return res.json({
        success: true,
        message: "User is already approved",
      });
    }

    await pool.execute(
      "UPDATE users SET is_approved = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      [targetUserId],
    );

    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
      [
        "user_approve",
        JSON.stringify({ approved_user_id: targetUserId }),
        req.user.userId,
      ],
    );

    res.json({
      success: true,
      message: "User approved successfully",
    });
  } catch (error) {
    console.error("Approve user error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to approve user",
      details: error.message,
    });
  }
});

app.delete("/api/users/:id", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const targetUserId = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
      return res.status(400).json({
        success: false,
        error: "Invalid user id",
      });
    }

    const requesterUserId = Number.parseInt(req.user.userId, 10);
    if (targetUserId === requesterUserId) {
      return res.status(400).json({
        success: false,
        error: "You cannot delete your own account",
      });
    }

    const [users] = await pool.execute(
      "SELECT id, role FROM users WHERE id = ? LIMIT 1",
      [targetUserId],
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    if (users[0].role === "admin") {
      const [adminCounts] = await pool.execute(
        "SELECT COUNT(*) as total_admins FROM users WHERE role = 'admin'",
      );
      const totalAdmins = Number(adminCounts[0]?.total_admins || 0);

      if (totalAdmins <= 1) {
        return res.status(400).json({
          success: false,
          error: "Cannot delete the last admin user",
        });
      }
    }

    await pool.execute("DELETE FROM users WHERE id = ?", [targetUserId]);

    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
      [
        "user_delete",
        JSON.stringify({ deleted_user_id: targetUserId }),
        requesterUserId || req.user.userId,
      ],
    );

    res.json({
      success: true,
      message: "User deleted successfully",
    });
  } catch (error) {
    console.error("Delete user error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to delete user",
      details: error.message,
    });
  }
});

// ==================== PRAYER REQUESTS ENDPOINTS ====================

app.post("/api/prayer-requests", authenticateToken, async (req, res) => {
  try {
    const { name, email, whatsapp_number, request, is_anonymous } = req.body;
    const userId = req.user.userId;
    const normalizedWhatsappNumber = String(whatsapp_number || "").trim();

    if (!request || !normalizedWhatsappNumber) {
      return res.status(400).json({
        success: false,
        error: "Prayer request text and WhatsApp number are required",
      });
    }

    const [result] = await pool.execute(
      `
      INSERT INTO prayer_requests (name, email, whatsapp_number, request, is_anonymous, user_id)
      VALUES (?, ?, ?, ?, ?, ?)
    `,
      [
        name,
        email,
        normalizedWhatsappNumber,
        request,
        is_anonymous === true || is_anonymous === "true",
        userId,
      ],
    );

    res.status(201).json({
      success: true,
      message: "Prayer request submitted successfully",
      prayer_request_id: result.insertId,
    });
  } catch (error) {
    console.error("Submit prayer request error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to submit prayer request",
      details: error.message,
    });
  }
});

app.get("/api/prayer-requests", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { status = "", search = "", page = 1, limit = 20 } = req.query;
    const parsedPage = Math.max(Number.parseInt(page, 10) || 1, 1);
    const parsedLimit = Math.min(
      Math.max(Number.parseInt(limit, 10) || 20, 1),
      200,
    );
    const offset = (parsedPage - 1) * parsedLimit;

    let query = `
      SELECT 
        pr.*,
        u.username as user_name,
        u.email as user_email,
        DATE_FORMAT(pr.created_at, '%Y-%m-%d %H:%i:%s') as created_at
      FROM prayer_requests pr
      LEFT JOIN users u ON pr.user_id = u.id
      WHERE 1=1
    `;
    const params = [];

    if (status) {
      query += ` AND pr.status = ?`;
      params.push(status);
    }

    if (search) {
      query += `
        AND (
          pr.name LIKE ?
          OR pr.request LIKE ?
          OR pr.email LIKE ?
          OR COALESCE(pr.whatsapp_number, '') LIKE ?
        )
      `;
      params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
    }

    query += ` ORDER BY pr.created_at DESC LIMIT ${parsedLimit} OFFSET ${offset}`;

    const [prayers] = await pool.execute(query, params);

    // Get counts by status
    const [counts] = await pool.execute(`
      SELECT 
        status,
        COUNT(*) as count
      FROM prayer_requests
      GROUP BY status
    `);

    const statusCounts = {};
    counts.forEach((item) => {
      statusCounts[item.status] = item.count;
    });

    res.json({
      success: true,
      prayer_requests: prayers,
      counts: statusCounts,
      pagination: {
        page: parsedPage,
        limit: parsedLimit,
        total: prayers.length,
      },
    });
  } catch (error) {
    console.error("Get prayer requests error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch prayer requests",
      details: error.message,
    });
  }
});

// ==================== COUNSELING REQUESTS ENDPOINTS ====================

app.post("/api/counseling-requests", authenticateToken, async (req, res) => {
  try {
    const {
      counseling_type,
      whatsapp_number,
      description,
      preferred_availability,
    } = req.body;
    const userId = req.user.userId;
    const normalizedWhatsappNumber = String(whatsapp_number || "").trim();

    if (!counseling_type || !description || !normalizedWhatsappNumber) {
      return res.status(400).json({
        success: false,
        error: "Counseling type, description, and WhatsApp number are required",
      });
    }

    const [result] = await pool.execute(
      `
      INSERT INTO counseling_requests (
        user_id,
        counseling_type,
        whatsapp_number,
        description,
        preferred_availability
      )
      VALUES (?, ?, ?, ?, ?)
    `,
      [
        userId,
        counseling_type,
        normalizedWhatsappNumber,
        description,
        preferred_availability,
      ],
    );

    res.status(201).json({
      success: true,
      message: "Counseling request submitted successfully",
      counseling_request_id: result.insertId,
    });
  } catch (error) {
    console.error("Submit counseling request error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to submit counseling request",
      details: error.message,
    });
  }
});

app.get("/api/counseling-requests", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { status = "", search = "", page = 1, limit = 20 } = req.query;
    const parsedPage = Math.max(Number.parseInt(page, 10) || 1, 1);
    const parsedLimit = Math.min(
      Math.max(Number.parseInt(limit, 10) || 20, 1),
      200,
    );
    const offset = (parsedPage - 1) * parsedLimit;

    let query = `
      SELECT
        cr.*,
        u.username as user_name,
        u.email as user_email,
        DATE_FORMAT(cr.created_at, '%Y-%m-%d %H:%i:%s') as created_at
      FROM counseling_requests cr
      LEFT JOIN users u ON cr.user_id = u.id
      WHERE 1=1
    `;
    const params = [];

    if (status) {
      query += ` AND cr.status = ?`;
      params.push(status);
    }

    if (search) {
      query += `
        AND (
          cr.description LIKE ?
          OR cr.counseling_type LIKE ?
          OR COALESCE(cr.whatsapp_number, '') LIKE ?
          OR COALESCE(u.username, '') LIKE ?
          OR COALESCE(u.email, '') LIKE ?
        )
      `;
      params.push(
        `%${search}%`,
        `%${search}%`,
        `%${search}%`,
        `%${search}%`,
        `%${search}%`,
      );
    }

    query += ` ORDER BY cr.created_at DESC LIMIT ${parsedLimit} OFFSET ${offset}`;

    const [requests] = await pool.execute(query, params);

    const [counts] = await pool.execute(`
      SELECT
        status,
        COUNT(*) as count
      FROM counseling_requests
      GROUP BY status
    `);

    const statusCounts = {};
    counts.forEach((item) => {
      statusCounts[item.status] = item.count;
    });

    res.json({
      success: true,
      counseling_requests: requests,
      counts: statusCounts,
      pagination: {
        page: parsedPage,
        limit: parsedLimit,
        total: requests.length,
      },
    });
  } catch (error) {
    console.error("Get counseling requests error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch counseling requests",
      details: error.message,
    });
  }
});

// ==================== SUPPORT ENDPOINTS ====================

app.get("/api/support/config", async (req, res) => {
  try {
    const settings = await getSettingsMap(PUBLIC_SUPPORT_SETTING_KEYS);

    res.json({
      success: true,
      support: buildPublicSupportConfig(settings),
    });
  } catch (error) {
    console.error("Get support config error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to load support configuration",
      details: error.message,
    });
  }
});

// ==================== DAILY PROMISE ENDPOINTS ====================

app.post("/api/admin/daily-promise", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { promise_text, author } = req.body;

    if (!promise_text) {
      return res.status(400).json({
        success: false,
        error: "Promise text is required",
      });
    }

    const [result] = await pool.execute(
      `
      INSERT INTO daily_promises (promise_text, author)
      VALUES (?, ?)
    `,
      [promise_text, author],
    );

    res.status(201).json({
      success: true,
      message: "Daily promise added successfully",
      promise_id: result.insertId,
    });
  } catch (error) {
    console.error("Add daily promise error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to add daily promise",
      details: error.message,
    });
  }
});

app.get("/api/daily-promise/latest", async (req, res) => {
  try {
    const [rows] = await pool.execute(
      "SELECT * FROM daily_promises ORDER BY created_at DESC LIMIT 1",
    );

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "No daily promise found",
      });
    }

    res.json({
      success: true,
      promise: rows[0],
    });
  } catch (error) {
    console.error("Get latest daily promise error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to get latest daily promise",
      details: error.message,
    });
  }
});

app.get("/api/daily-promises", async (req, res) => {
  try {
    const rawLimit = parseInt(req.query.limit, 10);
    const safeLimit = Number.isFinite(rawLimit) ? rawLimit : 5;
    const clampedLimit = Math.min(Math.max(safeLimit, 1), 100);

    const [rows] = await pool.execute(
      `SELECT * FROM daily_promises ORDER BY created_at DESC LIMIT ${clampedLimit}`,
    );

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "No daily promises found",
      });
    }

    res.json({
      success: true,
      promises: rows,
    });
  } catch (error) {
    console.error("Get daily promises error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to get daily promises",
      details: error.message,
    });
  }
});

// ==================== DEVOTION ENDPOINTS ====================

app.post("/api/admin/devotion-posts", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    await ensureDevotionTables();

    const { devotion_text, title, author } = req.body;

    if (!devotion_text) {
      return res.status(400).json({
        success: false,
        error: "Devotion text is required",
      });
    }

    const [result] = await pool.execute(
      `
      INSERT INTO devotion_posts (title, devotion_text, author)
      VALUES (?, ?, ?)
    `,
      [title, devotion_text, author],
    );

    res.status(201).json({
      success: true,
      message: "Devotion added successfully",
      devotion_id: result.insertId,
    });
  } catch (error) {
    console.error("Add devotion error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to add devotion",
      details: error.message,
    });
  }
});

app.get("/api/devotion-posts", async (req, res) => {
  try {
    await ensureDevotionTables();

    const rawLimit = parseInt(req.query.limit, 10);
    const safeLimit = Number.isFinite(rawLimit) ? rawLimit : 10;
    const clampedLimit = Math.min(Math.max(safeLimit, 1), 50);

    const [rows] = await pool.execute(
      `SELECT * FROM devotion_posts ORDER BY created_at DESC LIMIT ${clampedLimit}`,
    );

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "No devotion posts found",
      });
    }

    res.json({
      success: true,
      posts: rows,
    });
  } catch (error) {
    console.error("Get devotion posts error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to get devotion posts",
      details: error.message,
    });
  }
});

// ==================== COMMENT ENDPOINTS ====================

app.post("/api/comments", authenticateToken, async (req, res) => {
  try {
    await ensureDevotionTables();

    const postType = String(req.body.post_type || "")
      .trim()
      .toLowerCase();
    const postId = Number(req.body.post_id);
    const commentText = String(req.body.comment_text || "").trim();
    const allowedTypes = new Set(["devotion", "promise", "reading"]);

    if (!allowedTypes.has(postType)) {
      return res.status(400).json({
        success: false,
        error: "Invalid post type",
      });
    }

    if (!Number.isFinite(postId)) {
      return res.status(400).json({
        success: false,
        error: "Invalid post id",
      });
    }

    if (!commentText) {
      return res.status(400).json({
        success: false,
        error: "Comment text is required",
      });
    }

    const [result] = await pool.execute(
      `
      INSERT INTO comments (post_type, post_id, user_id, comment_text)
      VALUES (?, ?, ?, ?)
    `,
      [postType, postId, req.user.userId, commentText],
    );

    res.status(201).json({
      success: true,
      message: "Comment added successfully",
      comment_id: result.insertId,
    });
  } catch (error) {
    console.error("Add comment error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to add comment",
      details: error.message,
    });
  }
});

app.get("/api/comments", async (req, res) => {
  try {
    await ensureDevotionTables();

    const postType = String(req.query.post_type || "")
      .trim()
      .toLowerCase();
    const postId = Number(req.query.post_id);
    const allowedTypes = new Set(["devotion", "promise", "reading"]);

    if (!allowedTypes.has(postType)) {
      return res.status(400).json({
        success: false,
        error: "Invalid post type",
      });
    }

    if (!Number.isFinite(postId)) {
      return res.status(400).json({
        success: false,
        error: "Invalid post id",
      });
    }

    const [rows] = await pool.execute(
      `
      SELECT
        c.id,
        c.post_type,
        c.post_id,
        c.comment_text,
        c.created_at,
        u.username
      FROM comments c
      LEFT JOIN users u ON c.user_id = u.id
      WHERE c.post_type = ? AND c.post_id = ?
      ORDER BY c.created_at ASC
    `,
      [postType, postId],
    );

    res.json({
      success: true,
      comments: rows,
    });
  } catch (error) {
    console.error("Get comments error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to get comments",
      details: error.message,
    });
  }
});

// ==================== HEALTH & MONITORING ====================

// Health check endpoint
app.get("/api/health", async (req, res) => {
  try {
    // Test database connection
    await pool.execute("SELECT 1");

    // Check uploads directory
    const uploadsDir = join(__dirname, "uploads");
    const uploadsExists = existsSync(uploadsDir);

    if (!uploadsExists) {
      mkdirSync(uploadsDir, { recursive: true });
    }

    // Get system info
    const systemInfo = {
      node_version: process.version,
      platform: process.platform,
      memory_usage: process.memoryUsage(),
      uptime: process.uptime(),
      database: `connected (${DB_PROVIDER})`,
      storage_backend: isSupabaseStorageConfigured()
        ? `supabase:${SUPABASE_STORAGE_BUCKET}`
        : "local_uploads",
      storage_configured: isSupabaseStorageConfigured(),
      require_persistent_storage: REQUIRE_PERSISTENT_STORAGE,
      uploads_directory: uploadsExists ? "exists" : "created",
    };

    res.json({
      status: "healthy",
      timestamp: new Date().toISOString(),
      system: systemInfo,
    });
  } catch (error) {
    console.error("❤️ Healthcheck failed:", error.message);
    res.status(500).json({
      status: "unhealthy",
      error: error.message,
      timestamp: new Date().toISOString(),
    });
  }
});

// Connection test endpoint
app.get("/api/connection-test", (req, res) => {
  res.json({
    success: true,
    message: "Backend connection successful",
    backend: "Spiritual Center API",
    version: "2.0.0",
    database_provider: DB_PROVIDER,
    storage_backend: isSupabaseStorageConfigured()
      ? `supabase:${SUPABASE_STORAGE_BUCKET}`
      : "local_uploads",
    storage_configured: isSupabaseStorageConfigured(),
    require_persistent_storage: REQUIRE_PERSISTENT_STORAGE,
    timestamp: new Date().toISOString(),
    endpoints: {
      admin: "/api/admin/stats",
      materials: "/api/materials",
      analytics: "/api/analytics",
      settings: "/api/settings",
      notifications: "/api/notifications",
      users: "/api/users",
      auth_login: "/api/auth/login",
      auth_register: "/api/auth/register",
      auth_forgot_password: "/api/auth/forgot-password",
      auth_reset_password: "/api/auth/reset-password",
      auth_validate: "/api/auth/validate",
    },
  });
});

// ==================== ERROR HANDLING ====================

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Endpoint not found",
    path: req.path,
    method: req.method,
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error("Global error:", error);

  if (error.code === "LIMIT_FILE_SIZE") {
    const maxUploadMb =
      Math.round((MAX_UPLOAD_SIZE_BYTES / (1024 * 1024)) * 10) / 10;
    return res.status(400).json({
      success: false,
      error: `File too large. Maximum size is ${maxUploadMb}MB`,
    });
  }

  if (error instanceof multer.MulterError) {
    return res.status(400).json({
      success: false,
      error: "File upload error",
      details: error.message,
    });
  }

  res.status(500).json({
    success: false,
    error: "Internal server error",
    message: process.env.NODE_ENV === "development" ? error.message : undefined,
  });
});

// ==================== SERVER STARTUP ====================

process.on("uncaughtException", (error) => {
  console.error("💥 Uncaught Exception:", error);
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("💥 Unhandled Rejection at:", promise, "reason:", reason);
});

// Initialize and start server
(async () => {
  console.log(`DB provider selected: ${DB_PROVIDER}`);
  console.log("🔄 Starting server initialization...");

  try {
    console.log("🔄 Initializing database...");
    const dbInitialized = await initializeDatabase();

    if (dbInitialized) {
      console.log("✅ Database initialization complete");
    } else {
      console.warn(
        "⚠️  Database initialization had issues. The server will start but some features may fail.",
      );
    }

    // Create uploads directory if it doesn't exist
    const uploadsDir = join(__dirname, "uploads");
    if (!existsSync(uploadsDir)) {
      mkdirSync(uploadsDir, { recursive: true });
      console.log("✅ Created uploads directory");
    }

    const server = app.listen(PORT, () => {
      console.log(`✅ Server running on http://localhost:${PORT}`);
      console.log(
        `🚀 Admin Dashboard: http://localhost:${PORT}/admin-dashboard.html`,
      );
      console.log(`📊 API Base URL: http://localhost:${PORT}/api`);
      console.log(`📁 Uploads: http://localhost:${PORT}/uploads`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || "development"}`);
      console.log(
        `Storage backend: ${
          isSupabaseStorageConfigured()
            ? `supabase (${SUPABASE_STORAGE_BUCKET})`
            : "local /uploads"
        }`,
      );
      console.log(`DB provider: ${DB_PROVIDER}`);
      console.log("✨ Server is ready!");
    });

    server.on("error", (error) => {
      console.error("🔴 Server error:", error);
      if (error.code === "EADDRINUSE") {
        console.log(
          `Port ${PORT} is already in use. Trying ${Number(PORT) + 1}...`,
        );
        app.listen(Number(PORT) + 1);
      }
    });
  } catch (error) {
    console.error("🔴 Failed to start server:", error);
    process.exit(1);
  }
})();

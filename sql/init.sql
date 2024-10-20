-- Activate uuid extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS customers (
    "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    "name" VARCHAR(255) NOT NULL UNIQUE,
    "email" VARCHAR(255) NOT NULL UNIQUE,
    "phone" VARCHAR(255),
    "createdAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    "deletedAt" TIMESTAMP
);

CREATE TABLE IF NOT EXISTS organizations (
    "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    "name" VARCHAR(255) NOT NULL,
    "description" TEXT,
    "customerId" UUID NOT NULL,
    "createdAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    "deletedAt" TIMESTAMP,
    FOREIGN KEY (customerId) REFERENCES customers (id)
);

CREATE TABLE IF NOT EXISTS users (
    "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    "name" VARCHAR(255) NOT NULL,
    "email" VARCHAR(255) NOT NULL UNIQUE,
    "password" VARCHAR(255) NOT NULL,
    "organizationId" UUID NOT NULL,
    "createdAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    "deletedAt" TIMESTAMP,
    FOREIGN KEY (organizationId) REFERENCES organizations (id)
)

CREATE TABLE IF NOT EXISTS requests (
    "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    "name" VARCHAR(255) NOT NULL,
    "description" TEXT,
    "serialNumber" INT NOT NULL UNIQUE,
    "organizationId" UUID NOT NULL,
    "organizationUnit" VARCHAR(255),
    "streetAddress" VARCHAR(255),
    "locality" VARCHAR(255),
    "city" VARCHAR(255),
    "state" VARCHAR(255),
    "postalCode" VARCHAR(255),
    "country" VARCHAR(255) NOT NULL,
    "domainComponent" VARCHAR(255),
    "notBefore" TIMESTAMP NOT NULL,
    "notAfter" TIMESTAMP NOT NULL,
    "createdAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    "deletedAt" TIMESTAMP,
    FOREIGN KEY (organizationId) REFERENCES organizations (id)
);

CREATE TABLE IF NOT EXISTS authorities (
    "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    "name" VARCHAR(255) NOT NULL UNIQUE,
    "isRoot" BOOLEAN DEFAULT TRUE,
    "organizationId" UUID NOT NULL,
    "createdAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (organizationId) REFERENCES organizations (id)
);

CREATE TABLE IF NOT EXISTS certificates (
    "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    "commonName" VARCHAR(255) NOT NULL,
    "requestId" UUID NOT NULL,
    "authorityId" UUID NOT NULL,
    "createdAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    "s3Bucket" VARCHAR(255) NOT NULL,
    FOREIGN KEY (requestId) REFERENCES requests (id),
    FOREIGN KEY (authorityId) REFERENCES
);

CREATE TABLE IF NOT EXISTS revocations (
    "id" UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    "certificateId" UUID NOT NULL,
    "revokedAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    "revokedBy" UUID NOT NULL,
    "reason" VARCHAR(255) NOT NULL,
    FOREIGN KEY (certificateId) REFERENCES certificates (id),
    FOREIGN KEY (revokedBy) REFERENCES users (id)
);
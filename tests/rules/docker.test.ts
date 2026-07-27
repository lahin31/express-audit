import { describe, it, expect } from 'vitest';
import {
  dockerRunningAsRootRule,
  dockerLatestTagRule,
  dockerHealthcheckRule,
  dockerSecretsInImageRule,
  dockerCopyDotRule,
} from '../../src/rules/docker/dockerfile-security.js';
import { createContextFromFixture } from '../helpers.js';

const dockerCtx = (source: string) =>
  createContextFromFixture(source, 'Dockerfile');

describe('DOCKER001 – Running as root', () => {
  it('flags Dockerfile without USER instruction', () => {
    const ctx = dockerCtx(`FROM node:20-alpine\nRUN npm install\nCMD ["node", "index.js"]`);
    expect(dockerRunningAsRootRule.run(ctx)).toHaveLength(1);
  });

  it('flags Dockerfile with USER root', () => {
    const ctx = dockerCtx(`FROM node:20-alpine\nUSER root\nCMD ["node", "index.js"]`);
    expect(dockerRunningAsRootRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag Dockerfile with USER node', () => {
    const ctx = dockerCtx(`FROM node:20-alpine\nUSER node\nCMD ["node", "index.js"]`);
    expect(dockerRunningAsRootRule.run(ctx)).toHaveLength(0);
  });
});

describe('DOCKER002 – Latest tag', () => {
  it('flags FROM node:latest', () => {
    const ctx = dockerCtx(`FROM node:latest\nCMD ["node", "index.js"]`);
    expect(dockerLatestTagRule.run(ctx)).toHaveLength(1);
  });

  it('flags FROM node (no tag)', () => {
    const ctx = dockerCtx(`FROM node\nCMD ["node"]`);
    expect(dockerLatestTagRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag FROM node:20-alpine', () => {
    const ctx = dockerCtx(`FROM node:20-alpine\nCMD ["node"]`);
    expect(dockerLatestTagRule.run(ctx)).toHaveLength(0);
  });
});

describe('DOCKER003 – Missing HEALTHCHECK', () => {
  it('flags Dockerfile without HEALTHCHECK', () => {
    const ctx = dockerCtx(`FROM node:20-alpine\nCMD ["node", "index.js"]`);
    expect(dockerHealthcheckRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag Dockerfile with HEALTHCHECK', () => {
    const ctx = dockerCtx(`FROM node:20-alpine\nHEALTHCHECK CMD wget -q http://localhost:3000/health\nCMD ["node"]`);
    expect(dockerHealthcheckRule.run(ctx)).toHaveLength(0);
  });
});

describe('DOCKER004 – Secrets in image', () => {
  it('flags ENV with PASSWORD value', () => {
    const ctx = dockerCtx(`FROM node:20\nENV DB_PASSWORD=supersecret\nCMD ["node"]`);
    expect(dockerSecretsInImageRule.run(ctx)).toHaveLength(1);
  });

  it('flags ARG with SECRET value', () => {
    const ctx = dockerCtx(`FROM node:20\nARG API_SECRET=abc123\nCMD ["node"]`);
    expect(dockerSecretsInImageRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag harmless ENV', () => {
    const ctx = dockerCtx(`FROM node:20\nENV NODE_ENV=production\nCMD ["node"]`);
    expect(dockerSecretsInImageRule.run(ctx)).toHaveLength(0);
  });
});

describe('DOCKER005 – COPY . .', () => {
  it('flags COPY . .', () => {
    const ctx = dockerCtx(`FROM node:20\nCOPY . .\nRUN npm install`);
    expect(dockerCopyDotRule.run(ctx)).toHaveLength(1);
  });

  it('does not flag COPY package.json ./', () => {
    const ctx = dockerCtx(`FROM node:20\nCOPY package.json ./\nRUN npm install`);
    expect(dockerCopyDotRule.run(ctx)).toHaveLength(0);
  });
});

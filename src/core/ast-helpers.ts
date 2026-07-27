import type { NodePath } from '@babel/traverse';
import type * as BabelTypes from '@babel/types';
import _traverse from '@babel/traverse';
import type { File } from '@babel/types';

// @babel/traverse is a CJS module. Under Node ESM interop the default export
// may arrive either as the function directly or wrapped as { default: fn }.
// Normalise to always get the callable function.
const traverse: typeof _traverse =
  typeof _traverse === 'function'
    ? _traverse
    : (_traverse as unknown as { default: typeof _traverse }).default;

// Re-export for rules to use
export { traverse };

/**
 * Check if a node is a string literal with a specific value
 */
export function isStringLiteral(node: BabelTypes.Node | null | undefined): node is BabelTypes.StringLiteral {
  return node?.type === 'StringLiteral';
}

/**
 * Get string value from a node (handles string literals and template literals)
 */
export function getStringValue(node: BabelTypes.Node | null | undefined): string | null {
  if (!node) return null;
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis[0]?.value.cooked || null;
  }
  return null;
}

/**
 * Check if an expression is process.env.SOMETHING
 */
export function isProcessEnv(node: BabelTypes.Node | null | undefined): boolean {
  if (!node) return false;
  if (node.type !== 'MemberExpression') return false;
  const { object, property } = node as BabelTypes.MemberExpression;
  if (object.type !== 'MemberExpression') return false;
  const { object: envObj, property: envProp } = object;
  const isProcessNode = envObj.type === 'Identifier' && (envObj as BabelTypes.Identifier).name === 'process';
  const isEnvProp = envProp.type === 'Identifier' && (envProp as BabelTypes.Identifier).name === 'env';
  return isProcessNode && isEnvProp;
}

/**
 * Get the callee name of a call expression (e.g., "require", "app.use")
 */
export function getCalleeName(node: BabelTypes.CallExpression): string | null {
  const { callee } = node;
  if (callee.type === 'Identifier') return callee.name;
  if (callee.type === 'MemberExpression') {
    const obj = callee.object;
    const prop = callee.property;
    const objName = obj.type === 'Identifier' ? obj.name : null;
    const propName = prop.type === 'Identifier' ? prop.name : null;
    if (objName && propName) return `${objName}.${propName}`;
  }
  return null;
}

/**
 * Find all call expressions matching a pattern
 */
export function findCallExpressions(
  ast: File,
  patterns: string[]
): BabelTypes.CallExpression[] {
  const found: BabelTypes.CallExpression[] = [];
  
  traverse(ast, {
    CallExpression(path: NodePath<BabelTypes.CallExpression>) {
      const name = getCalleeName(path.node);
      if (name && patterns.some(p => name === p || name.endsWith(`.${p}`))) {
        found.push(path.node);
      }
    },
  });

  return found;
}

/**
 * Check if a function has a specific argument pattern
 */
export function getObjectProperty(
  obj: BabelTypes.ObjectExpression,
  key: string
): BabelTypes.Node | null {
  for (const prop of obj.properties) {
    if (prop.type === 'ObjectProperty') {
      const k = prop.key;
      if (
        (k.type === 'Identifier' && k.name === key) ||
        (k.type === 'StringLiteral' && k.value === key)
      ) {
        return prop.value;
      }
    }
  }
  return null;
}

/**
 * Check if an AST node has a specific boolean property set to false
 */
export function isBoolFalse(node: BabelTypes.Node | null | undefined): boolean {
  if (!node) return false;
  return node.type === 'BooleanLiteral' && !(node as BabelTypes.BooleanLiteral).value;
}

/**
 * Check if an AST node has a specific boolean property set to true
 */
export function isBoolTrue(node: BabelTypes.Node | null | undefined): boolean {
  if (!node) return false;
  return node.type === 'BooleanLiteral' && (node as BabelTypes.BooleanLiteral).value;
}

/**
 * Find all require/import statements for a specific package
 */
export function findImports(ast: File, packageName: string): boolean {
  let found = false;

  traverse(ast, {
    ImportDeclaration(path: NodePath<BabelTypes.ImportDeclaration>) {
      if (path.node.source.value === packageName ||
          path.node.source.value.startsWith(`${packageName}/`)) {
        found = true;
      }
    },
    CallExpression(path: NodePath<BabelTypes.CallExpression>) {
      const callee = path.node.callee;
      if (callee.type === 'Identifier' && callee.name === 'require') {
        const arg = path.node.arguments[0];
        if (
          arg?.type === 'StringLiteral' &&
          (arg.value === packageName || arg.value.startsWith(`${packageName}/`))
        ) {
          found = true;
        }
      }
    },
  });

  return found;
}

/**
 * Get the line number from a Babel AST node
 */
export function getNodeLine(node: BabelTypes.Node): number {
  return node.loc?.start.line || 0;
}

/**
 * Get the column number from a Babel AST node
 */
export function getNodeColumn(node: BabelTypes.Node): number {
  return node.loc?.start.column || 0;
}

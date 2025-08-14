import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Lists all dependencies in project based on filter
 *
 * @param {string} [filter='']
 * @returns {Promise<string[]>}
 */
function listAvailableProviders(filter = ''): string[] {
  const packageDeps: string[] = [];
  try {
    const packageJsonPath = path.resolve(process.cwd(), 'package.json');
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8')) as { dependencies: [] };

    Object.keys({ ...packageJson.dependencies }).forEach((d) => {
      if (d.includes(filter.toLowerCase())) {
        packageDeps.push(d);
      }
    });
  } catch (err) {}
  return packageDeps;
}

/**
 * Dynamically import a package using the package name
 *
 * @async
 * @param {string} packageName
 * @returns {Promise<unknown>}
 */
async function dynamicPackageImport(packageName: string): Promise<unknown> {
  return await import(packageName);
}

export { listAvailableProviders, dynamicPackageImport };

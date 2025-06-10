import * as fs from 'fs';
import * as path from 'path';

/**
 * Lists all dependencies in project based on filter
 *
 * @async
 * @param {string} [filter='']
 * @returns {Promise<string[]>}
 */
async function listAvailableProviders(filter: string = ''): Promise<string[]> {
  const packageDeps: string[] = [];
  try {
    const packageJsonPath = path.resolve(process.cwd(), 'package.json');
    const packageJson: { dependencies: [] } = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));

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

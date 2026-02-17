# How to Release a New Version

This document describes the steps to release a new version of the unite client-py package to PyPI.

## Prerequisites

- You have write access to the repository
- You have permission to create GitHub releases

## Release Process

### 1. Update the Version Number

Before merging your changes to `main-unite`, update the version in `fhirclient/client.py`:

```python
__version__ = "X.Y.Z+unite.N"
```

The version format follows:
- `X.Y.Z` - Base version from upstream fhirclient
- `+unite.N` - Unite-specific version suffix (increment N for each release)

Example: `4.4.0+unite.1` → `4.4.0+unite.2`

### 2. Merge to main-unite

1. Create a pull request with your changes (including the version bump)
2. Ensure CI tests pass (runs on all PRs via `.github/workflows/ci.yaml`)
3. Get the PR reviewed and approved
4. Merge the PR to `main-unite`

### 3. Create a GitHub Release

The PyPI publish workflow (`.github/workflows/pypi.yaml`) is triggered when a GitHub release is created.

1. Go to the repository's **Releases** page
2. Click **"Draft a new release"**
3. Click **"Choose a tag"** and create a new tag matching your version (e.g., `v4.4.0+unite.2`)
4. Set the **Target** to `main-unite`
5. Set the **Release title** to the version (e.g., `v4.4.0+unite.2`)
6. Add release notes describing the changes
7. Click **"Publish release"**

### 4. Verify the Release

After publishing the release:

1. Check the **Actions** tab to verify the PyPI workflow completed successfully
2. Verify the package is available on PyPI: https://pypi.org/project/fhirclient/

## Workflow Details

The release workflow (`.github/workflows/pypi.yaml`) performs the following steps:

1. Checks out the code at the release tag
2. Installs build dependencies
3. Builds the package using `python -m build`
4. Publishes to PyPI using trusted publishing (no API token needed)

## Troubleshooting

### PyPI workflow failed

- Check the Actions tab for error details
- Ensure the version in `fhirclient/client.py` doesn't already exist on PyPI
- Verify PyPI trusted publishing is configured correctly for the repository

### Version mismatch

- The version in `fhirclient/client.py` should match the Git tag (without the `v` prefix)
- Example: Tag `v4.4.0+unite.2` should have `__version__ = "4.4.0+unite.2"`

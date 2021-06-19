Tests for the Github REST API

# How To

1. Clone the repo
2. Navigate to the repository root and run

```
git update-index --assume-unchanged token.py
```

**This will prevent you from accidently commiting tokens to the repository.**

3. Create the personal access tokens requested in `token.py` for your test account
4. Run the test cases.

You can do this either by directly calling Python

```
python3 github_api.py <test_index>
```

or by using the existing [tasks](.vscode/tasks.json) for vscode.

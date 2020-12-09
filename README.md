# length-extesion-attack
### SHA1, SHA-256's length extension attack
It generates payload and hash value for length extension against SHA1 and SHA-256.

You can generate attack payload and hash by modifying 3 lines below as what you want.

##### SHA1
* length_extension_sha1/length_extension_sha1.py
    ``` python
    EXPECTED_KEY_LEN = 32
    ORIGIN_STRING = b"This Is An Original Data"
    INJECT_STRING = b"I'm Attacker"
    ```

##### SHA-256
* length_extension_sha256/length_extension_sha256.py
    ``` python
    EXPECTED_KEY_LEN = 32
    ORIGIN_STRING = b"This Is An Original Data"
    INJECT_STRING = "I'm Attacker"
    ```

import hashlib

def calculate_hashes(file_path):
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    hash_sha256 = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_md5.update(chunk)
            hash_sha1.update(chunk)
            hash_sha256.update(chunk)
    
    return {
        'MD5': hash_md5.hexdigest(),
        'SHA-1': hash_sha1.hexdigest(),
        'SHA-256': hash_sha256.hexdigest()
    }

# tính hash
initial_hashes = calculate_hashes('DATA.TXT')
print("Initial Hashes:")
for algo, value in initial_hashes.items():
        print(f"{algo}: {value}")
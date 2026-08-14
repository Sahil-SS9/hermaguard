import os

def save_upload(file_storage):
    dest = os.path.join("/srv/uploads", file_storage.filename)
    file_storage.save(dest)
    return dest

from pypdf import PdfReader

def extract_metadata(file_path):
    reader = PdfReader(file_path)
    metadata = {}

    if reader.metadata:
        for k, v in reader.metadata.items():
            metadata[k.strip("/")] = str(v)

    return metadata

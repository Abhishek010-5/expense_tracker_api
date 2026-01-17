from PIL import Image
import io

def reduce_image_from_file(input_file, target_kb=100, max_dimension=1024):
    """
    input_file: The file object from your web framework (e.g., request.files['image'])
    target_kb: The maximum desired size in Kilobytes
    """
    target_bytes = target_kb * 1024
    quality = 90
    
    # 1. Read the input file into Pillow
    # We wrap it in BytesIO in case the input is raw bytes
    try:
        img = Image.open(input_file)
    except Exception as e:
        # If input_file is already bytes, use io.BytesIO(input_file)
        img = Image.open(io.BytesIO(input_file))

    # 2. Standardize to RGB (removes transparency/alpha channels for JPEG)
    if img.mode != "RGB":
        img = img.convert("RGB")

    # 3. Initial resize (maintains aspect ratio)
    img.thumbnail((max_dimension, max_dimension), Image.Resampling.LANCZOS)

    # 4. Compression Loop
    while True:
        buffer = io.BytesIO()
        img.save(buffer, format="JPEG", quality=quality, optimize=True)
        
        data = buffer.getvalue()
        if len(data) <= target_bytes or quality <= 20:
            break
        
        quality -= 10 # Drop quality if still too big

    return data # Returns binary data ready for the DB
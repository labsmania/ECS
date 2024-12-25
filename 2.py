from pypdf import PdfReader

keywords = ['/js', 'JavaScript', '/AA', '/open_action']
reader = PdfReader('1.pdf')
pdf_safe = True

for page_num, page in enumerate(reader.pages):
    text = page.extract_text()
    if text:
        for keyword in keywords:
            if keyword in text:
                print(f"Malicious PDF detected: Keyword '{keyword}' found on page {page_num + 1}")
                pdf_safe = False
                break
    else:
        print(f"Page {page_num + 1} has no extractable text.")

if pdf_safe:
    print("The PDF is safe.")

import gradio as gr
import json
import tempfile
from pathlib import Path
from tzEnc2.main import encrypt, decrypt

# ---------- Encrypt Handler ----------
def encrypt_handler(message, password, redundancy, digest_passphrase, input_file):
    """
    If input_file is provided, read that as UTF-8 text.
    Otherwise, use the message text. Then call tzEnc2.encrypt(),
    serialize to compact JSON, write to a temp .tzenc file, and return.
    """
    try:
        # 1) Determine message source
        if input_file is not None and input_file.name:
            message = Path(input_file.name).read_text(encoding="utf-8")

        if not message or not password:
            raise ValueError("Message and password are required.")

        # 2) Perform encryption
        data = encrypt(
            password=password,
            redundancy=redundancy,
            message=message,
            digest_passphrase=digest_passphrase or ""
        )

        # 3) Serialize to compact JSON
        json_str = json.dumps(data, separators=(",", ":"), indent=None)

        # 4) Write to a temporary .tzenc file
        temp = tempfile.NamedTemporaryFile(delete=False, suffix=".tzenc", mode="w", encoding="utf-8")
        temp.write(json_str)
        temp.close()

        # 5) Return (display JSON, download path, status)
        return json_str, temp.name, "✅ Encryption successful."
    except Exception as e:
        return None, None, f"❌ Encryption failed: {str(e)}"

# ---------- Decrypt Handler ----------
def decrypt_handler(json_text, file_obj, password, digest_passphrase):
    """
    If json_text is nonempty, use that. Otherwise, read file_obj.
    Then call tzEnc2.decrypt(), write the result to a temp .txt file, and return.
    """
    try:
        # 1) Determine source of encrypted JSON
        if json_text and json_text.strip():
            content = json_text
        elif file_obj is not None and file_obj.name:
            content = Path(file_obj.name).read_text(encoding="utf-8")
        else:
            raise ValueError("Either encrypted JSON text or a .tzenc file must be provided.")

        if not password:
            raise ValueError("Password is required.")

        # 2) Parse JSON and decrypt
        json_data = json.loads(content)
        message = decrypt(
            password=password,
            json_data=json_data,
            digest_passphrase=digest_passphrase or ""
        )

        # 3) Write decrypted message to a temp .txt file
        temp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w", encoding="utf-8")
        temp.write(message)
        temp.close()

        # 4) Return (display plain text, download path, status)
        return message, temp.name, "✅ Decryption successful."
    except Exception as e:
        return None, None, f"❌ Decryption failed: {str(e)}"


# ---------- Encrypt Tab Layout ----------
encrypt_inputs = [
    gr.Textbox(label="Message (leave empty to use file)", lines=4, placeholder="Type your message here..."),
    gr.Textbox(label="Password", type="password"),
    gr.Slider(1, 10, value=3, step=1, label="Redundancy"),
    gr.Textbox(label="Digest Passphrase (optional)", type="password"),
    gr.File(label="Upload Message File (.txt)", file_types=[".txt"])
]

encrypt_outputs = [
    gr.Textbox(label="Encrypted JSON Output", lines=10),
    gr.File(label="Download .tzenc"),
    gr.Textbox(label="Status / Error", lines=2, interactive=False)
]

encrypt_tab = gr.Interface(
    fn=encrypt_handler,
    inputs=encrypt_inputs,
    outputs=encrypt_outputs,
    title="Encrypt a Message",
    description="Encrypt a message using tzEnc2",
    allow_flagging="never"
)


# ---------- Decrypt Tab Layout ----------
decrypt_inputs = [
    gr.Textbox(label="Encrypted JSON Text", lines=10, placeholder="Paste encrypted JSON here..."),
    gr.File(label="Upload Encrypted File (.tzenc)", file_types=[".tzenc"]),
    gr.Textbox(label="Password", type="password"),
    gr.Textbox(label="Digest Passphrase (optional)", type="password")
]

decrypt_outputs = [
    gr.Textbox(label="Decrypted Message", lines=10),
    gr.File(label="Download .txt"),
    gr.Textbox(label="Status / Error", lines=2, interactive=False)
]

decrypt_tab = gr.Interface(
    fn=decrypt_handler,
    inputs=decrypt_inputs,
    outputs=decrypt_outputs,
    title="Decrypt a Message",
    description="Decrypt a tzEnc2 encrypted message",
    allow_flagging="never"
)


# ---------- Run App ----------
def main():
    gr.TabbedInterface([encrypt_tab, decrypt_tab], ["Encrypt", "Decrypt"]).launch()


if __name__ == "__main__":
    main()

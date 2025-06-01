import gradio as gr
import json
from pathlib import Path
from tzEnc2.main import encrypt, decrypt


# ---------- Encrypt ----------
def encrypt_handler(message, password, redundancy, digest_passphrase, input_file):
    try:
        if input_file is not None:
            input_path = Path(input_file)
            if input_path.exists():
                message = input_path.read_text(encoding="utf-8")

        if not message or not password:
            return None, "Error: message and password are required."

        data = encrypt(
            password=password,
            redundancy=redundancy,
            message=message,
            digest_passphrase=digest_passphrase or None,
        )
        json_str = json.dumps(data, indent=2)

        # Save output to file
        output_path = Path("message.tzenc")
        output_path.write_text(json_str, encoding="utf-8")

        return json_str, str(output_path)
    except Exception as e:
        return None, f"Encryption failed: {e}"


# ---------- Decrypt ----------
def decrypt_handler(file_obj, password, digest_passphrase):
    try:
        if file_obj is None:
            return None, "Please upload a .tzenc file."

        file_path = Path(file_obj)
        if not file_path.exists():
            return None, "Uploaded file not found."

        json_str = file_path.read_text(encoding="utf-8")
        json_data = json.loads(json_str)

        message = decrypt(
            password=password,
            json_data=json_data,
            digest_passphrase=digest_passphrase or None,
        )

        output_path = Path("message.txt")
        output_path.write_text(message, encoding="utf-8")

        return message, str(output_path)
    except Exception as e:
        return None, f"Decryption failed: {e}"


# ---------- Encrypt Tab ----------
encrypt_inputs = [
    gr.Textbox(label="Message (leave empty to use file)", lines=4),
    gr.Textbox(label="Password", type="password"),
    gr.Slider(1, 10, value=3, step=1, label="Redundancy"),
    gr.Textbox(label="Digest Passphrase (optional)", type="password"),
    gr.File(label="Upload Message File (UTF-8 .txt)", file_types=[".txt"]),
]

encrypt_outputs = [
    gr.Textbox(label="Encrypted JSON Output", lines=10),
    gr.File(label="Download .tzenc"),
]

encrypt_tab = gr.Interface(
    fn=encrypt_handler,
    inputs=encrypt_inputs,
    outputs=encrypt_outputs,
    title="Encrypt a Message",
    allow_flagging="never",
)

# ---------- Decrypt Tab ----------
decrypt_inputs = [
    gr.File(label="Upload Encrypted File (.tzenc)", file_types=[".tzenc"]),
    gr.Textbox(label="Password", type="password"),
    gr.Textbox(label="Digest Passphrase (optional)", type="password"),
]

decrypt_outputs = [
    gr.Textbox(label="Decrypted Message", lines=10),
    gr.File(label="Download .txt"),
]

decrypt_tab = gr.Interface(
    fn=decrypt_handler,
    inputs=decrypt_inputs,
    outputs=decrypt_outputs,
    title="Decrypt a Message",
    allow_flagging="never",
)


# ---------- Run App ----------
def main():
    gr.TabbedInterface([encrypt_tab, decrypt_tab], ["Encrypt", "Decrypt"]).launch()

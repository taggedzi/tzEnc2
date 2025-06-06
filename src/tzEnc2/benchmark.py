# benchmark.py
import os
import time
import matplotlib.pyplot as plt
import pandas as pd

# Import your real encrypt/decrypt and CHARACTER_SET from tzEnc2
from tzEnc2.main import encrypt, decrypt

# --------------- Constants ---------------
TEMPLATE_1K_STR = """Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin a placerat felis, eu laoreet arcu. Aenean commodo tincidunt dictum. Maecenas tempus porta purus, eget rutrum nunc. Nulla rutrum, quam at condimentum mattis, erat dui pretium velit, nec suscipit quam eros id nisi. Morbi sed semper purus. Integer vestibulum ipsum eget augue congue, in luctus sapien semper. Donec ultrices gravida lectus sed facilisis. Morbi tellus urna, tincidunt at dignissim quis, porta vel nisi.

Curabitur consectetur lectus nunc, et cursus enim fermentum a. Donec sodales pellentesque vehicula. Fusce sit amet aliquet ante. Fusce rutrum enim quam, et commodo nunc molestie nec. Nunc sed sodales ligula. Nunc vel sapien et ex placerat sodales. Sed sagittis nisl turpis, a mattis purus egestas et. Sed ac molestie nulla.

Phasellus ut sagittis massa. Aliquam porta congue ipsum, vel laoreet tortor tempor et. Nulla sodales odio sapien, et tristique libero cursus vehicula. Cras vitae dictum felis. In consectetur t"""


# Generate a 1000-character “plain text”
def generate_plain_text(desired_length: int) -> str:
    """
    Build a string of exactly `desired_length` characters by repeating and trimming `template`.

    Args:
        desired_length (int): The length of the final output string.
        template (str): The base string to repeat from (e.g. 1000 characters long).

    Returns:
        str: A string exactly `desired_length` characters long.
    
    Raises:
        ValueError: If desired_length is negative or template is empty.
    """
    template = TEMPLATE_1K_STR
    if desired_length < 0:
        raise ValueError("desired_length must be non-negative.")
    if not template:
        raise ValueError("template string must not be empty.")

    repeat_count = (desired_length + len(template) - 1) // len(template)
    extended = (template * repeat_count)[:desired_length]
    return extended

# The special string (as provided by you) that forces an extremely large padded list:
SPECIAL_STRING = (
    "\tľȾ̾чՈ٫ݰࢋচଌঃඹ༯ၜᅤቫ፻ᒈᖈᚉឿᣠᨐ᭗ᱦᵼṼᾊ⃑⇤⋤⏤┒☒✒⠒⤒⨒⬒Ⱅⴚ⹈⽷゙ㆠ㊭㎭㒭㖭㚭㞭㢭㦭㪭㮭㲭㶭㺭㾭䂭䆭䊭䎭䒭䖭䚭䞭䢭䦭䪭䮭䲭䶭亭侭傭冭劭厭咭喭嚭垭墭妭媭宭岭嶭庭徭悭憭抭掭播断暭枭梭榭檭殭沭涭溭澭炭熭犭玭璭疭皭瞭碭禭窭箭粭維纭羭肭膭芭莭蒭薭蚭螭袭覭読训貭趭躭辭邭醭銭鎭钭閭隭鞭颭馭骭鮭鲭鶭麭龭ꂭꆭꊭꎭ꒰ꖹꛍꟴꤓꨧꭥ걱굱깱꽱끱녱뉱덱둱땱뙱띱롱륱멱뭱뱱뵱빱뽱쁱셱쉱썱쑱앱왱 읱족쥱쩱쭱챱쵱칱콱큱텱퉱퍱푱핱홱흱礪慎ﯓﳓ﷼－𐀫𐅝𐌱𐑪𐖏𐛗𐡒𐧟𐬨𐳙𐽾𑃜𑈇𑐈𑗗𑠘𑧤𑰜𑶍𒂟𒆟𒊟𒐅𒔑𓁪𓅪𓉪𓍪𔐻𔔻𔘻𖣴𖧴𖬓𖼹𗂝𗆝𗊝𗎝𗒝𗖝𗚝𗞝𗢝𗦝𗪝𗮝𗲝𗶝𗺝𗾝𘂝𘆝𘊝𘎝𘒝𘖝𘚝𘞝𘢥𘦥𘪥𘮥𘲥𛂹𛇿𛰃𜽿𝂻𝇏𝐚𝔫𝘲𝜴𝠶𝤶𝨶𞊚𞢔𞴤🁛"
)

# --------------- Benchmark Logic ---------------

def benchmark_case(case_name: str, message: str, password: str = "benchmark"):
    """
    For the given message, loop over workers=1..cpu_count and chunksize=1,2,4,..,1024.
    Measure encryption and decryption times using the real functions.
    Returns a list of dicts with (case, workers, chunksize, time_enc, time_dec).
    """
    cpu_count = os.cpu_count() or 1
    max_workers_list = list(range(1, cpu_count + 1))
    chunksize_list = [2**i for i in range(0, 11)]  # [1,2,4,8,...,1024]

    results = []
    redundancy = 3
    digest_passphrase = "test"

    for workers in max_workers_list:
        for chunksize in chunksize_list:
            # Time encryption (calls your real `encrypt` which builds the grid, etc.)
            t0 = time.perf_counter()
            json_data = encrypt(
                password=password,
                redundancy=redundancy,
                message=message,
                digest_passphrase=digest_passphrase,
                max_workers=workers,
                chunksize=chunksize
            )
            t_enc = time.perf_counter() - t0

            # Time decryption (calls your real `decrypt`)
            t0 = time.perf_counter()
            _ = decrypt(
                password=password,
                json_data=json_data,
                digest_passphrase=digest_passphrase,
                max_workers=workers,
                chunksize=chunksize
            )
            t_dec = time.perf_counter() - t0

            results.append({
                'case': case_name,
                'workers': workers,
                'chunksize': chunksize,
                'time_enc': t_enc,
                'time_dec': t_dec
            })
            print(f"[{case_name}] workers={workers}, chunksize={chunksize}, enc={t_enc:.3f}s, dec={t_dec:.3f}s")

    return results

def main():
    # 1) Generate a 10 000-character "plain text" message
    plain_10k = generate_plain_text(5000)

    # 2) Run benchmarks for both “plain_10k” and “special” cases
    all_results = []
    all_results += benchmark_case("plain_10k", plain_10k)
    all_results += benchmark_case("special", SPECIAL_STRING)

    # 3) Convert to DataFrame, compute throughput (tasks/sec)
    df = pd.DataFrame(all_results)
    df['speed_enc'] = df['time_enc'].apply(lambda t: 2000 / t if t > 0 else 0)
    df['speed_dec'] = df['time_dec'].apply(lambda t: 2000 / t if t > 0 else 0)

    # 4) Save the raw results to CSV
    df.to_csv("real_benchmark_results.csv", index=False)
    print("\nSaved full results to real_benchmark_results.csv")

    # 5) Plot heatmaps for encryption & decryption for each case
    for mode in ['speed_enc', 'speed_dec']:
        for case_name in df['case'].unique():
            subset = df[df['case'] == case_name]
            pivot = subset.pivot(index='workers', columns='chunksize', values=mode)

            plt.figure(figsize=(8, 6))
            title = f"{case_name} {'Encryption' if mode == 'speed_enc' else 'Decryption'} Speed"
            plt.title(title)
            plt.imshow(pivot, aspect='auto', origin='lower', interpolation='nearest')
            plt.colorbar(label='Tasks/sec')
            plt.xlabel("Chunksize")
            plt.ylabel("Workers")
            plt.xticks(range(len(pivot.columns)), pivot.columns, rotation=45)
            plt.yticks(range(len(pivot.index)), pivot.index)
            plt.tight_layout()
            plt.show()

if __name__ == "__main__":
    main()

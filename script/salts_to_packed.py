import csv
import argparse
from collections import defaultdict


def process_rows(reader: csv.DictReader, salt_column: str, nonce_column: str, leading_zeros_column: str):
    salts_by_zeroes = defaultdict(list)
    owner = None
    for row in reader:
        salt = bytes.fromhex(row[salt_column].lstrip("0x"))
        if owner is None:
            owner = salt[:20]
        else:
            assert owner == salt[:20], \
                f"Non uniform owner across salts: 0x{owner.hex()} != 0x{salt[:20].hex()}"
        nonce = int(row[nonce_column])
        leading_zeros = int(row[leading_zeros_column])
        salts_by_zeroes[leading_zeros].append((salt, nonce))
    all_salts = sorted(salts_by_zeroes.items(), key=lambda x: x[0])
    packed = b"".join(b"".join(nonce.to_bytes(1, "big") +
                      salt[-12:] for salt, nonce in salts) for _, salts in all_salts)
    start_indices = []
    start_index = 0
    for _, salts in all_salts:
        start_indices.append(start_index)
        start_index += len(salts)

    return owner, packed, start_indices


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file_path", type=str,
                        help="The path to the CSV file containing the salts")
    parser.add_argument("--salt-column", type=str, default="salt",
                        help="The name of the column containing the salts")
    parser.add_argument("--nonce-column", type=str, default="salt_nonce",
                        help="The name of the column containing the nonces")
    parser.add_argument("--leading-zeros-column", type=str, default="leading_zeros",
                        help="The name of the column containing the leading zeros")
    args = parser.parse_args()

    with open(args.file_path, "r") as f:
        reader = csv.DictReader(f)
        owner, packed, start_indices = process_rows(reader, args.salt_column, args.nonce_column,
                                                    args.leading_zeros_column)

    print(f"packed: 0x{packed.hex()}")
    print(f"owner: 0x{owner.hex()}")
    print(f"packed length: {len(packed):,}")
    print(f"start_indices: {start_indices}")


if __name__ == "__main__":
    main()

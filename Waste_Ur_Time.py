import subprocess
import random
import string
import argparse
import os

def generate_random_passcode(length=32):
    characters = string.digits + string.ascii_uppercase
    return ''.join(random.choice(characters) for _ in range(length))

def main(args):
    input_file = args.package
    output_directory = args.output

    passcode_found = False

    while not passcode_found:
        passcode = generate_random_passcode()
        # passcode = "00000000000000000000000000000000" ; this was used for debugging
        Sc0Path = os.path.join(output_directory, "Sc0")
        Image0Path = os.path.join(output_directory, "Image0")
        command = f"orbis-pub-cmd.exe img_extract --passcode {passcode} \"{input_file}\" \"{output_directory}\""
        
        try:
            print(f"[+] {command}")
            completed_process = subprocess.run(command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

            if os.path.exists(Sc0Path) and os.path.exists(os.path.join(Image0Path)):
                print(f"[+] Last Passcode used: {passcode}")
                print(f"[+] Output directory with 'Sc0': {output_directory}")
                break  
            else:
                print("[+] Nothing found... trying next passcode.")
        except subprocess.CalledProcessError as e:
            print("[+] Wrong Passcode!\n")
            #print(f"[+] Sc0Path: {Sc0Path}")
            #print(f"[+] Image0Path: {Image0Path}")

    print("[+] We did it! #SampepsimanLovesFloppas")

if __name__ == "__main__":
    print("Created by Hoppers - Enjoy wasting ur time!")
    parser = argparse.ArgumentParser(description="Find the correct passcode for a package file.")
    parser.add_argument("-p", "--package", required=True, help="Path to the package file.")
    parser.add_argument("-o", "--output", required=True, help="Output directory for extraction.")
    args = parser.parse_args()
    main(args)

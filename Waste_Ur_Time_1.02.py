import subprocess
import random
import string
import argparse
import os
import threading

passcode_found = False

def generate_random_passcode(length=32):
    characters = string.digits + string.ascii_letters + '-_'
    return ''.join(random.choice(characters) for _ in range(length))

def brute_force_passcode(input_file, output_directory, num_threads):
    global passcode_found

    while not passcode_found:
        passcode = generate_random_passcode()

        Sc0Path = os.path.join(output_directory, "Sc0")
        Image0Path = os.path.join(output_directory, "Image0")
        command = f"orbis-pub-cmd.exe img_extract --passcode {passcode} \"{input_file}\" \"{output_directory}\""
        
        try:
            print(f"[+] {command}")
            completed_process = subprocess.run(command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

            if os.path.exists(Sc0Path) and os.path.exists(os.path.join(Image0Path)):
                print(f"[+] Last Passcode used: {passcode}")
                print(f"[+] Output directory with 'Sc0': {output_directory}")
                passcode_found = True
                break  
            else:
                pass  
        except subprocess.CalledProcessError as e:
            pass  

def main(args):
    brute_force_threads = []
    for _ in range(args.threads):
        brute_force_thread = threading.Thread(target=brute_force_passcode, args=(args.package, args.output, args.threads))
        brute_force_threads.append(brute_force_thread)
        brute_force_thread.start()

    for thread in brute_force_threads:
        thread.join()

    print("[+] We did it! #SampepsimanLovesFloppas")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find the correct passcode for a package file.")
    parser.add_argument("-p", "--package", required=True, help="Path to the package file.")
    parser.add_argument("-o", "--output", required=True, help="Output directory for extraction.")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads for passcode brute-force (default: 1)")
    args = parser.parse_args()

    print("Created by Hoppers - Enjoy wasting ur time!")
    main(args)
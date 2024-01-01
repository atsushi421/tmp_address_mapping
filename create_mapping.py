import csv
from tqdm import tqdm


MEMORY_SIZE = 16777216

APP1_START_V = '0x040000000'
APP1_START_P = '0x104000000'

def get_vaddr_details(hex_vaddr: str) -> dict:
    vaddr_details = {}

    b_value = bin(int(hex_vaddr, 16))[2:].zfill(48)
    vaddr_details['0b_vaddr[47:39]'] = '0b' + b_value[0:9]
    vaddr_details['vaddr[47:39]'] = int(vaddr_details['0b_vaddr[47:39]'], 2)
    vaddr_details['0b_vaddr[38:30]'] = '0b' + b_value[9:18]
    vaddr_details['vaddr[38:30]'] = int(vaddr_details['0b_vaddr[38:30]'], 2)
    vaddr_details['0b_vaddr[29:21]'] = '0b' + b_value[18:27]
    vaddr_details['vaddr[29:21]'] = int(vaddr_details['0b_vaddr[29:21]'], 2)
    vaddr_details['0b_vaddr[20:12]'] = '0b' + b_value[27:36]
    vaddr_details['vaddr[20:12]'] = int(vaddr_details['0b_vaddr[20:12]'], 2)
    vaddr_details['0b_vaddr[11:0]'] = '0b' + b_value[36:48]
    vaddr_details['0x_vaddr[11:0]'] = hex(int(vaddr_details['0b_vaddr[11:0]'], 2))
   
    return vaddr_details

def get_paddr_details(hex_paddr: str, hex_vaddr_11_0: str) -> dict:
    paddr_details = {}

    paddr_details['-offset'] = hex(int(hex_paddr, 16) - int(hex_vaddr_11_0, 16))
    paddr_details['-offset_12_shifted'] = hex(int(paddr_details['-offset'], 16) >> 12)
   
    return paddr_details

def add_hex(hex_value: str, add_value: int) -> str:
    return hex(int(hex_value, 16) + add_value)

if __name__ == '__main__':
    CSV_PATH = 'app1.csv'
    with open(CSV_PATH, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['vaddr', '0b_vaddr[47:39]', 'vaddr[47:39]', '0b_vaddr[38:30]', 'vaddr[38:30]', '0b_vaddr[29:21]', 'vaddr[29:21]', '0b_vaddr[20:12]', 'vaddr[20:12]', '0b_vaddr[11:0]', '0x_vaddr[11:0]', 'paddr', '-offset_12_shifted'])

        for i in tqdm(range(1000)):
            vaddr = add_hex(APP1_START_V, i)
            vaddr_details = get_vaddr_details(vaddr)
            paddr = add_hex(APP1_START_P, i)
            paddr_details = get_paddr_details(
                paddr, vaddr_details['0x_vaddr[11:0]'])
            writer.writerow([vaddr, vaddr_details['0b_vaddr[47:39]'], vaddr_details['vaddr[47:39]'], vaddr_details['0b_vaddr[38:30]'], vaddr_details['vaddr[38:30]'], vaddr_details['0b_vaddr[29:21]'], vaddr_details['vaddr[29:21]'], vaddr_details['0b_vaddr[20:12]'], vaddr_details['vaddr[20:12]'], vaddr_details['0b_vaddr[11:0]'], vaddr_details['0x_vaddr[11:0]'], paddr, paddr_details['-offset_12_shifted']])
        
import csv


def load_data_from_csv(path, sni_path):
    """
    The main function is to count CSV files (total_ File) and generate a label file that can be used for LSTM/GRU.
    :param
    csv_path: CSV file path to process（total_file obtained in main_process.py）
    SNI_info_path：Export all label sets（CSV file）
    :return:Generated label file.
    """
    sni_dict = dict()
    try:
        with open(sni_path, 'r+', newline='') as sf:
            sni_reader = csv.reader(sf)
            for sni_row in sni_reader:
                if sni_row[0] not in sni_dict.keys() and len(sni_row[0]):
                    sni_dict[sni_row[0]] = 1
    except Exception:
        pass
    with open(path, 'r') as f:
        with open(sni_path, 'a+', newline='') as sf:
            sni_writer = csv.writer(sf)
            csv_reader = csv.reader(f, delimiter=',')
            odd_even_flag = 'odd'  # 奇数行是流标签，偶数行是应用标签
            for row in csv_reader:
                if odd_even_flag == 'even':
                    odd_even_flag = 'odd'
                    continue
                elif odd_even_flag == 'odd':
                    odd_even_flag = 'even'
                if row[0] not in sni_dict.keys() and len(row[0]):
                    sni_dict[row[0]] = 1
                    sni_writer.writerow([
                        row[0],
                        len(sni_dict)-1
                    ])
                    print(row[0], len(sni_dict)-1)


if __name__ == "__main__":
    csv_path = 'F:/topic3-家族应用识别/data/google_and_apple_all.csv'
    SNI_info_path = 'F:/topic3-家族应用识别/data/Flag_service2number_all.csv'
    load_data_from_csv(csv_path, SNI_info_path)

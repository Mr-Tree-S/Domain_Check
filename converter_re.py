import pandas as pd
import os
import argparse


def converter(input_list):
    # Read the Excel file
    df = pd.read_excel(input_list)
    # Save DataFrame as a text file
    output_file = os.path.splitext(input_list)[0] + ".txt"
    df.to_csv(output_file, sep='|', index=False, header=False)


# Parse arguments
parser = argparse.ArgumentParser(description='Convert text to xlsx format')
parser.add_argument('-l', '--list', type=str, help='Input file list to be converted to xlsx format')
args = parser.parse_args()

# Main execution
if args.list:
    input_list = args.list
    converter(input_list)
else:
    # Display usage information
    print('Usage: python3 converter_re.py -l <file_list>')

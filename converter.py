import pandas as pd
import os
import argparse

def converter(input_list):
    # Read text file into DataFrame and specify column names
    df = pd.read_csv(input_list, sep='|', header=None, names=["Domains", "Found_OR_Not", "Affected_Subdomain"])
    # Convert DataFrame to Excel format
    output_file = os.path.splitext(input_list)[0] + ".xlsx"
    df.to_excel(output_file, index=False)


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
    print('Usage: python3 converter.py -l <file_list>')

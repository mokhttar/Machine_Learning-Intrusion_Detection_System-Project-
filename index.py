import numpy as np
import pandas as pd
import os

# List all files in dirs and subdirs
def get_all_files(root_dir):
    all_files = []
    if not os.path.exists(root_dir):
        print(f"Directory {root_dir} does not exist!")
        return all_files
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    print(f"Found {len(all_files)} files in {root_dir} and subdirectories")
    return all_files


# Sort files by type
def sort_files(files):
    csv_array_files = []
    text_array_files = []
    log_array_files = []
    for file in files:
        if file.endswith('.csv'):
            csv_array_files.append(file)
        elif file.endswith('.txt') or file.endswith('.arff'):
            text_array_files.append(file)
        elif file.endswith('.log'):
            log_array_files.append(file)
    return csv_array_files, text_array_files, log_array_files


# Read CSV in chunks and store in map(i found the encoding issue so i just tested to fix it )
def open_csv_files(csv_files):
    chunk_size = 1000
    file_map = {}
    
    for file in csv_files:
        chunks = []
        try:
            for chunk in pd.read_csv(file, chunksize=chunk_size, encoding='utf-8'):
                chunks.append(chunk)
        except UnicodeDecodeError:
            for chunk in pd.read_csv(file, chunksize=chunk_size, encoding='latin1'):
                chunks.append(chunk)
        except Exception as e:
            print(f"Error reading file {file}: {e}")
            continue
        if chunks:
            file_map[file] = chunks
            print(f"Loaded {len(chunks)} chunks for file {file}")
        else:
            print(f"No chunks loaded for file {file}")

    return file_map


#function to open text files
def open_text_files(text_files):
   attributes = []
   lines_whitout_attribute = []
   for file in text_files:
       with open(file,'r') as f:
           for line in f:
               #skiping empty lines
               if not line or line.startswith('%'):
                   continue
               else:
                   if line.startswith("@attribute"):
                       attributes.append(line.split(' ')[1])
                   else:
                       lines_whitout_attribute.append(line)
                       
   return attributes,lines_whitout_attribute



#function to open log files (for later)
def open_log_files(log_files):
    pass

#function ==> entrainment data set ==> important features ===> [features] 
def extract_final_features_fromDatasets():
    final_features = []
    pass


def main():
    files = get_all_files('./Data')
    csv_array_files, text_array_files, log_array_files = sort_files(files)

#opening and handling csv files (just for testing)

    csv_file_map = open_csv_files(csv_array_files)

    if csv_file_map:
        first_file = list(csv_file_map.keys())[0]  
        full_df = pd.concat(csv_file_map[first_file], ignore_index=True)
        print(full_df.columns)
        print(full_df.head())
    else:
        print("No CSV files loaded successfully.")
        
    # opening and handling text files (just for testing)
    #extracting attribute from my text data set
    text_attributes,text_lines_whitout_attribute =open_text_files(text_array_files)
    



#this shit from django that i never understoood but still doing it so nban 9atal
if __name__ =="__main__":
    main()

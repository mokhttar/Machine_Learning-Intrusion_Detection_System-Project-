import numpy as np
import pandas as pd
import os

#ai calls
from openai import OpenAI
# from gpt4all import GPT4All


from sklearn.model_selection import train_test_split
# to encode categories
from sklearn.preprocessing import OneHotEncoder
#encode  the labels in my case the class (A/N)
from sklearn.preprocessing import LabelEncoder


#For the model of Decission Tree
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.tree import export_text
from sklearn.metrics import classification_report
from xgboost import XGBClassifier



#my dictionary fo columns i hope that my fucked up logique will work
column_mapping = { 
    # IPs
    'src_ip': [' Source IP', 'Src IP', 'src_ip', 'src ip'],
    'dst_ip': [' Destination IP', 'Dst IP', 'dst_ip', 'dst ip'],

    # Ports
    'src_port': [' Source Port', 'Src Port', 'src_port', 'src port'],
    'dst_port': [' Destination Port', 'Dst Port', 'dst_port', 'dst port'],

    # Protocol
    'protocol': [' Protocol', 'protocol'],

    # Packet / Flow features
    'flow_duration': [' Flow Duration', 'flow_duration', 'Flow Duration'],
    'total_fwd_packets': [' Total Fwd Packets', 'Total Fwd Packets', 'Fwd Packets'],
    'total_bwd_packets': [' Total Backward Packets', 'Total Backward Packets', 'Bwd Packets'],
    'total_length_fwd': ['Total Length of Fwd Packets', 'Total Length Fwd Packets'],
    'total_length_bwd': [' Total Length of Bwd Packets', 'Total Length Bwd Packets'],
    'fwd_pkt_len_max': [' Fwd Packet Length Max', 'Fwd Packet Length Max'],
    'fwd_pkt_len_min': [' Fwd Packet Length Min', 'Fwd Packet Length Min'],
    'fwd_pkt_len_mean': [' Fwd Packet Length Mean', 'Fwd Packet Length Mean'],
    'fwd_pkt_len_std': [' Fwd Packet Length Std', 'Fwd Packet Length Std'],
    'bwd_pkt_len_max': ['Bwd Packet Length Max', ' Bwd Packet Length Max'],
    'bwd_pkt_len_min': [' Bwd Packet Length Min', 'Bwd Packet Length Min'],
    'bwd_pkt_len_mean': [' Bwd Packet Length Mean', 'Bwd Packet Length Mean'],
    'bwd_pkt_len_std': [' Bwd Packet Length Std', 'Bwd Packet Length Std'],
    'flow_bytes_per_s': ['Flow Bytes/s', ' Flow Bytes/s'],
    'flow_packets_per_s': [' Flow Packets/s', 'Fwd Packets/s', ' Bwd Packets/s'],
    
    # IAT (Inter-arrival times)
    'flow_iat_mean': [' Flow IAT Mean', 'Flow IAT Mean'],
    'flow_iat_std': [' Flow IAT Std', 'Flow IAT Std'],
    'flow_iat_max': [' Flow IAT Max', 'Flow IAT Max'],
    'flow_iat_min': [' Flow IAT Min', 'Flow IAT Min'],
    'fwd_iat_total': ['Fwd IAT Total'],
    'fwd_iat_mean': [' Fwd IAT Mean'],
    'fwd_iat_std': [' Fwd IAT Std'],
    'fwd_iat_max': [' Fwd IAT Max'],
    'fwd_iat_min': [' Fwd IAT Min'],
    'bwd_iat_total': ['Bwd IAT Total'],
    'bwd_iat_mean': [' Bwd IAT Mean'],
    'bwd_iat_std': [' Bwd IAT Std'],
    'bwd_iat_max': [' Bwd IAT Max'],
    'bwd_iat_min': [' Bwd IAT Min'],

    # Flags
    'fwd_psh_flags': ['Fwd PSH Flags', ' Fwd PSH Flags'],
    'bwd_psh_flags': [' Bwd PSH Flags', 'Bwd PSH Flags'],
    'fwd_urg_flags': [' Fwd URG Flags', 'Fwd URG Flags'],
    'bwd_urg_flags': [' Bwd URG Flags', 'Bwd URG Flags'],
    'fin_flag_count': ['FIN Flag Count'],
    'syn_flag_count': [' SYN Flag Count', 'SYN Flag Count'],
    'rst_flag_count': [' RST Flag Count', 'RST Flag Count'],
    'psh_flag_count': [' PSH Flag Count', 'PSH Flag Count'],
    'ack_flag_count': [' ACK Flag Count', 'ACK Flag Count'],
    'urg_flag_count': [' URG Flag Count', 'URG Flag Count'],

    # Packet size & flow statistics
    'avg_packet_size': [' Average Packet Size', 'Packet Length Mean'],
    'packet_len_std': [' Packet Length Std'],
    'packet_len_var': [' Packet Length Variance'],

    # Other metrics
    'label': [' Label', 'Attack', 'Class'],
    'flow_id': ['Flow ID'],
    'timestamp': [' Timestamp', 'Timestamp'],
    'active_mean': ['Active Mean', ' Active Mean'],
    'active_std': [' Active Std'],
    'idle_mean': ['Idle Mean', ' Idle Mean'],
    'idle_std': [' Idle Std']
}


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
               
               if not line or line.startswith('%'):
                   continue
               else:
                   if line.startswith("@attribute"):
                       current_line=line.split(' ')[1]
                       if current_line not in attributes:
                           attributes.append(current_line)
                     
                   else:
                       lines_whitout_attribute.append(line.strip())
                       
   return attributes,lines_whitout_attribute



#handle csv files chuks from my map 
def unify_chunks_in_one_dataframe_csv(csv_file_map):            
    all_chunks=[]  #store all chunks of all files 
    for chunks in csv_file_map.values():
        all_chunks.extend(chunks)
    full_df=pd.concat(all_chunks,ignore_index=True)
    full_df.to_csv("./Results/csv_result.csv",index=False)
    return full_df



def create_csv_from_attributes_text(attributes, lines, csv_file=None, delimiter=','):
    # Split each line into a list of values
    rows = []
    for line in lines:
        row = line.split(delimiter)
        rows.append(row)
        
    df = pd.DataFrame(rows, columns=attributes)
    df.to_csv(csv_file, index=False, sep=delimiter)
    
    return df



#this function will unify all the data in one data frame 
def UnifyData(final_csv_dataframe,final_text_dataframe):
    final_dataframe= pd.concat([final_csv_dataframe,final_text_dataframe],ignore_index=True)
    print("Generating your final data set please wait this proccess will take a while....^-^")
    final_dataframe.to_csv("./Results/final_results.csv")
    return final_dataframe


#function to open log files (for later)
# def open_log_files(log_files):
#     pass

#clearning the data from my final csv file  and  extract the columns and place the values in there correct values
def preProcessing(final_file, dictionary_of_final_features):
    chunk_size = 500
    processed_chunks = []

    reverse_map = {}
    for canonical_name, variants in dictionary_of_final_features.items():
        for v in variants:
            reverse_map[v.strip().lower()] = canonical_name

    try:
        for chunk in pd.read_csv(final_file, chunksize=chunk_size):

            chunk.columns = [col.strip().lower() for col in chunk.columns]

            rename_dict = {}
            for col in chunk.columns:
                if col in reverse_map:
                    rename_dict[col] = reverse_map[col]

            chunk = chunk.rename(columns=rename_dict)

            expected_features = list(dictionary_of_final_features.keys())
            chunk = chunk[[c for c in chunk.columns if c in expected_features]]

            processed_chunks.append(chunk)

        if not processed_chunks:
            print("No valid data found after preprocessing.")
            return None

        final_df = pd.concat(processed_chunks, ignore_index=True)

       
        for col in expected_features:
            if col not in final_df.columns:
                final_df[col] = np.nan

       
        final_df.to_csv("./Results/final_preprocessed.csv", index=False)
        print("Renaming and handling columns with  correct values completed successfully.")

        return final_df

    except Exception as e:
        print(f"Error during preprocessing of {final_file}: {e}")
        return None
    

# this part i didnt code it i get it from gpt becuase when i did it solo i needed 25 terabite of ram so my shit can work fuck that
# def encode_and_prepare_for_ml(df):
#     if 'label' not in df.columns:
#         raise ValueError("Label column not found")

#     df = df[df['label'].notna()].copy()

#     label_encoder = LabelEncoder()
#     df['label'] = label_encoder.fit_transform(df['label'].astype(str))

#     print("\nLabel Encoding:")
#     for cls, idx in zip(label_encoder.classes_, range(len(label_encoder.classes_))):
#         print(f"{cls} -> {idx}")

  
#     identifiers = ['src_ip', 'dst_ip', 'flow_id', 'timestamp']
#     df = df.drop(columns=[c for c in identifiers if c in df.columns])

#     if 'protocol' in df.columns:
#         df['protocol'] = df['protocol'].astype(str)
#         df['protocol'] = LabelEncoder().fit_transform(df['protocol'])


#     feature_cols = df.drop(columns=['label']).columns

#     for col in feature_cols:
#         df[col] = pd.to_numeric(df[col], errors='coerce')


#     df = df.replace([np.inf, -np.inf], np.nan)

#     # Median is safer than zero for IDS
#     df[feature_cols] = df[feature_cols].fillna(df[feature_cols].median())

#     X = df.drop(columns=['label'])
#     y = df['label']

#     print(f"\nFinal dataset shape: X={X.shape}, y={y.shape}")

#     return X, y

def encode_and_prepare_for_ml(df):
    if 'label' not in df.columns:
        raise ValueError("Label column not found")

    # Remove rows with missing labels
    df = df[df['label'].notna()].copy()

    # Ensure label is integer
    df['label'] = df['label'].astype(int)

    # Convert multi-class to binary
    # 0 = BENIGN, 1 = ATTACK
    for i in range(len(df)):
        if df.at[i, 'label'] == 0:
            df.at[i, 'label'] = 0
        else:
            df.at[i, 'label'] = 1

    print("\nBinary Labels:")
    print("0 -> BENIGN")
    print("1 -> ATTACK")

    # Drop identifiers
    identifiers = ['src_ip', 'dst_ip', 'flow_id', 'timestamp']
    for col in identifiers:
        if col in df.columns:
            df.drop(columns=col, inplace=True)

    # Encode protocol if exists
    if 'protocol' in df.columns:
        df['protocol'] = df['protocol'].astype(str)
        le = LabelEncoder()
        df['protocol'] = le.fit_transform(df['protocol'])

    # Convert features to numeric
    feature_cols = df.drop(columns=['label']).columns
    for col in feature_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    # Handle inf and NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    for col in feature_cols:
        df[col].fillna(df[col].median(), inplace=True)

    # Split
    X = df.drop(columns=['label'])
    y = df['label']

    print(f"\nFinal dataset shape: X={X.shape}, y={y.shape}")
    print("\nLabel distribution:")
    print(y.value_counts())

    return X, y




def decision_tree_pattern_generator(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        stratify=y,
        random_state=42
    )

    tree = DecisionTreeClassifier(
        max_depth=10,
        class_weight='balanced',
        random_state=42
    )

    tree.fit(X_train, y_train)

    print("\n=== Decision Tree Evaluation ===\n")
    print(classification_report(y_test, tree.predict(X_test)))

    rules = export_text(tree, feature_names=list(X.columns))

    print("\n--- DECISION TREE PATTERNS ---\n")
    # print(rules)

    return tree,rules


def random_forest_pattern_generator(X, y, tree_index=0):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        stratify=y,
        random_state=42
    )

    forest = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )

    forest.fit(X_train, y_train)

    print("\n=== Random Forest Evaluation ===\n")
    print(classification_report(y_test, forest.predict(X_test)))

    # Extract ONE tree for interpretation
    estimator = forest.estimators_[tree_index]

    rules = export_text(estimator, feature_names=list(X.columns))

    print(f"\n--- RANDOM FOREST PATTERNS (Tree {tree_index}) ---\n")
    # print(rules)


    return forest



def xgboost_pattern_generator(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        stratify=y,
        random_state=42
    )

    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective='binary:logistic',
        eval_metric='logloss',
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train, y_train)

    print("\n=== XGBoost Evaluation ===\n")
    print(classification_report(y_test, model.predict(X_test)))

    # Dump boosted tree rules
    booster = model.get_booster()
    rules = booster.get_dump(with_stats=True)

    print("\n--- XGBOOST PATTERNS (First 3 Trees) ---\n")
    for i, tree in enumerate(rules[:3]):
        print(f"\nTree {i}:\n")
        print(tree)

    return model



def generate_ids_rules(patterns, api_key):

    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )
    
    # Craft a detailed prompt to convert patterns to IDS rules
    prompt = f"""
    Convert the following machine learning patterns into IDS rules in Snort/Suricata format.
    Each rule should follow the proper syntax and include appropriate actions, protocols, 
    source/destination IP addresses, ports, and options based on the patterns provided.
    
    Patterns:
    {patterns}
    
    Please generate comprehensive IDS rules that would detect these patterns in network traffic.
    Each rule should include:
    1. Action (alert, drop, etc.)
    2. Protocol
    3. Source IP and port
    4. Destination IP and port
    5. Options (msg, content, classtype, priority, etc.)
    
    Format each rule according to Snort/Suricata standards.
    """
    
    try:
        completion = client.chat.completions.create(
            extra_headers={
                "HTTP-Referer": "IDS Rule Generator",  
                "X-Title": "IDS Rule Generator",      
            },
            model="mistralai/devstral-2512:free",
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert in cybersecurity and intrusion detection systems. Your task is to convert machine learning patterns into effective IDS rules following Snort/Suricata syntax."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
        
        # Extract and return the generated rules
        return completion.choices[0].message.content
        
    except Exception as e:
        print(f"Error generating IDS rules: {e}")
        return None


def save_ids_rules(rules, filename="./Results/generated_ids_rules.txt"):
    """
    Save the generated IDS rules to a file.
    
    Args:
        rules (str): The generated IDS rules
        filename (str): The file path to save the rules
    """
    if rules:
        try:
            with open(filename, 'w') as f:
                f.write(rules)
            print(f"IDS rules saved to {filename}")
        except Exception as e:
            print(f"Error saving IDS rules: {e}")
    else:
        print("No rules to save.")
    

def generate_ids_rules_local_api(pattern):
    model = GPT4All("gpt4all‑lora‑quantized‑ggml")
    prompt = f"Analyze the following decision tree pattern and extract meaningful IDS rules:\n\n{pattern}\n\nProvide the rules in a clear format and generate a file in Snort format for these rules."
    out = model.generate(prompt)
    print(out)
    return out


def main():

    files = get_all_files('./Data')
    csv_array_files, text_array_files, log_array_files = sort_files(files)

    if not csv_array_files:
        print("No CSV files found.")
        return

    csv_file_map = open_csv_files(csv_array_files)

    if not csv_file_map:
        print("Failed to load CSV files.")
        return


    final_csv_dataframe = unify_chunks_in_one_dataframe_csv(csv_file_map)


    if text_array_files:
        attributes, text_lines = open_text_files(text_array_files)
        final_text_dataframe = create_csv_from_attributes_text(
            attributes,
            text_lines,
            "./Results/results_text.csv"
        )

        final_dataframe = UnifyData(final_csv_dataframe, final_text_dataframe)
    else:
        final_dataframe = final_csv_dataframe
        final_dataframe.to_csv("./Results/final_results.csv", index=False)

    print("Final dataset created.")


    final_preprocessed = preProcessing(
        "./Results/final_results.csv",
        column_mapping
    )

    if final_preprocessed is None:
        print("Preprocessing failed.")
        return

    print("Preprocessing completed.")


    final_df = pd.read_csv("./Results/final_preprocessed.csv")
    X, y = encode_and_prepare_for_ml(final_df)


    # Decision Tree (rules)
    dt_model, dt_rules = decision_tree_pattern_generator(X, y)

    # Random Forest 
    rf_model = random_forest_pattern_generator(X, y, tree_index=0)

    #XGBoost
    xgb_model = xgboost_pattern_generator(X, y)
    
    
    api_key = "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"
    rules=generate_ids_rules(api_key=api_key, patterns=dt_rules)
    save_ids_rules(rules)
    # generate_ids_rules_local_api(patterns=dt_rules)
    print("\n=== PIPELINE FINISHED SUCCESSFULLY ===")
       


if __name__ == "__main__":
    main()

    


#!/bin/bash
# Function to analyze directories, these are the pimary of interest
analyze_directories() {
    selected_paths=(
        "rules"
        "rules-threat-hunting"
        "rules-emerging-threats"
    )

    #Set up sigma cli
    sigma plugin install elasticsearch
    sigma plugin install sysmon

    # Get the current working directory of the script
    SCRIPT_DIR=$(pwd)

    # Navigate to the parent directory of the script directory (i.e. Sigma Fork)
    TARGET_DIR=$(realpath "$SCRIPT_DIR/../..")

    # Set date times to limit the commit searching
    current_datetime=$(date -u +"%Y-%m-%d")
    since_date=$(date -u -d "-30 days" +"%Y-%m-%d")
    echo "Date Now: $current_datetime" >&2
    echo "Date Since: $since_date" >&2

    # Initialize data array holder that will be sent to Tines
    declare -a data_array

    #Loop through the paths of interest
    for path in "${selected_paths[@]}"; do
        folder_path="$TARGET_DIR/$path"
        
        # Check if path contains '/' - this is just formatting insurance
        if [[ "$folder_path" =~ '/' ]]; then
            folder_path="$(echo "$folder_path" | sed -r 's/[xyz]+/_/g')"
        fi

        # Initialize an empty array to store git output
        git_array=()

        # Use git log to grab the commit messages between starting and ending date
        # A quick method of getting exactly what we want without recursing the whole directories one by one
        echo "folder path: $folder_path" >&2
        gitInfo=$(git -C "$TARGET_DIR" log --pretty=format: --name-only --since=$since_date --until=$current_datetime -- "$folder_path")
        
        # Loop through each dir (i.e. file path in commit messages found)
        for dir in $gitInfo; do
            git_array+=("$dir")
        done

        # Analyze if the files contain relevant info
        for file in "${git_array[@]}"; do
            file_content="$TARGET_DIR/$file"

            if [[ -f "$file_content" ]]; then
                content=$(cat "$file_content")

                # This is to start filtering at this point and only getting what would most likely be relevant
                # Filter can be expanded for more granular results
               if [[ ! "$content" =~ 'status: test' && ! "$content" =~ 'status: experimental' && "$file_content" =~ \.yml$ ]]; then
                    echo "All conditions met!" >&2  # Print to stderr
                    
                    # Extract the required fields using yq
                    title=$(yq e '.title' "$file_content")
                    id=$(yq e '.id' "$file_content")
                    author=$(yq e '.author' "$file_content")
                    status=$(yq e '.status' "$file_content")
                    description=$(yq e '.description' "$file_content")
                    references=$(yq e '.references | tojson' "$file_content")
                    date_modified=$(yq e '.modified' "$file_content")
                    logsource=$(yq e '.logsource | tojson' "$file_content")

                    echo "$title" >&2

                    #Invoke sigma-cli from bash
                    query=$(sigma convert -t lucene -p sysmon -p ecs_windows -f kibana_ndjson $file_content)

                    # Format the extracted fields into json object
                    data_entry=$(jq -n --arg title "$title" --arg id "$id" --arg author "$author"  --arg status "$status" --arg description "$description" --args references "$references" --arg date_modified "$date_modified"  --arg logsource "$logsource"  --args query "$query"'
                      {
                        "title": $title,
                        "id": $id,
                        "author": $author,
                        "status": $status,
                        "description": $description,
                        "references": $references,
                        "date_modified": $date_modified,
                        "logsource": $logsource,
                        "query": $query
                      }'
                    )

                    echo "$data_entry" >&2

                    # Add the data entry to the data array
                    data_array+=("$data_entry")
                else 
                    echo "Conditions not met for $file_content." >&2  # Print to stderr
                fi
            else
                echo "File not found: $file_content" >&2  # Print to stderr
            fi
            echo "$file"
        done
    done

    #result=$(printf '%s\n' "${data_array[@]}" | jq -s '.')

    # Check if the array is empty if so do nothing - add check in action yml file to halt pipeline if nothing new to add
    if [ ${#data_array[@]} -eq 0 ]; then
        echo "The array is empty." >&2
        check=${#data_array[@]} 
        echo "Check is $check" >&2
    else
        # Loop through entries and append to file. This will allow us to access the file and manipulate the json array further
        for entry in "${data_array[@]}"; do
            echo "$entry" >> out.txt
        done
    fi
   
}

# Main function
main() {
    analyze_directories
}
# Execute main function and capture the output in a variable
main 
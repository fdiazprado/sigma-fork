#!/bin/bash
# Function to analyze directories
analyze_directories() {
    selected_paths=(
        "rules"
        "rules-threat-hunting"
        "rules-emerging-threats"
    )
    # Get the directory of the script
    SCRIPT_DIR=$(pwd)
    # Navigate to the parent directory of the script directory
    TARGET_DIR=$(realpath "$SCRIPT_DIR/../..")
    current_datetime=$(date -u +"%Y-%m-%d")
    since_date=$(date -u -d "-8 days" +"%Y-%m-%d")
    # Initialize data array holder that will be sent to Tines
    declare -a data_array
    for path in "${selected_paths[@]}"; do
        folder_path="$TARGET_DIR/$path"
        
        # Check if path contains '/'
        if [[ "$folder_path" =~ '/' ]]; then
            folder_path="$(echo "$folder_path" | sed -r 's/[xyz]+/_/g')"
        fi
        # Initialize an empty array to store git output
        git_array=()
        # Read each line into the array
        #while IFS= read -r line; do
        #    git_array+=("$line")
        #done < <(git -C "$TARGET_DIR" log --pretty=format: --name-only --since="$since_date" -- "$folder_path")
        gitInfo=$(git -C "$TARGET_DIR" log --pretty=format: --name-only --since="$since_date" -- "$folder_path")
        for dir in $gitInfo; do
            git_array+=("$dir")
        done

        # Analyze if the files contain relevant info
        for file in "${git_array[@]}"; do
            file_content="$TARGET_DIR/$file"

            if [[ -f "$file_content" ]]; then
                content=$(cat "$file_content")

               if [[ ! "$content" =~ 'status: test' && ! "$content" =~ 'status: experimental' && "$file_content" =~ \.yml$ ]]; then
                    echo "All conditions met!" >&2  # Print to stderr
                     # Extract the required fields using yq
                    title=$(yq e '.title' "$file_content")
                    id=$(yq e '.id' "$file_content")
                    status=$(yq e '.status' "$file_content")
                    description=$(yq e '.description' "$file_content")
                    #logsource=$(yq e '.logsource | tojson' "$file_content")

                    data_entry=$(jq -n --arg title "$title" --arg id "$id" --arg status "$status" --arg description "$description" '
                      {
                        "title": $title,
                        "id": $id,
                        "status": $status,
                        "description": $description
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

    # Output the final data array to stdout
    for entry in "${data_array[@]}"; do
        echo "$entry" >> out.txt
    done
   # for entry in "${data_array[@]}"; do
   #     echo "$entry" >> out.txt
   # done
}

# Main function
main() {
    analyze_directories
}
# Execute main function and capture the output in a variable
main 
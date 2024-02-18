from pymisp import ExpandedPyMISP
import os

def main():
    # Get environment variables
    path = os.environ.get('path')
    misp_url = os.environ.get('misp_url')
    misp_key = os.environ.get('misp_key')
    verify_ssl = False  # Set to True if you want to verify SSL certificate

    # Initialize MISP connection
    misp = ExpandedPyMISP(misp_url, misp_key, verify_ssl)

    # Define attribute types to search for
    attribute_types = ['domain']

    # Iterate through attribute types
    for attribute_type in attribute_types:
        try:
            # Search for attributes of the specified type with warning list enforcement
            search_result = misp.search(controller='attributes', enforce_warninglist=True, type_attribute=attribute_type)
            
            # Write search results to a file
            output_file_path = f'/var/ossec/etc/lists/enforced_warninglist_{attribute_type}_values_wazuh'
            write_search_results_to_file(search_result, output_file_path)

        except Exception as e:
            # Handle exceptions and print error message
            print(f"Error occurred for attribute type '{attribute_type}': {e}")
            break

def write_search_results_to_file(search_result, output_file_path):
    # Write search results to a file
    with open(output_file_path, 'w') as file:
        for attribute in search_result['Attribute']:
            file.writelines(attribute['value'] + ':\n')

if __name__ == "__main__":
    main()

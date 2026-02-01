"""Verify that the OpenAPI schema now properly documents the response format"""
import requests
import json

API_BASE = "https://agentic-honey-pot-e7mc.onrender.com"

print("=" * 80)
print("Verifying OpenAPI Schema Fix")
print("=" * 80)

try:
    # Get the OpenAPI schema
    response = requests.get(f"{API_BASE}/openapi.json", timeout=10)
    schema = response.json()
    
    print(f"\n✅ OpenAPI Schema Retrieved")
    
    # Check POST /honeypot REQUEST BODY Schema
    print(f"\n📋 POST /honeypot REQUEST BODY Schema:")
    post_op = schema['paths']['/honeypot']['post']
    
    if 'requestBody' in post_op:
        print("✅ Request Body is DEFINED")
        content = post_op['requestBody'].get('content', {})
        if 'application/json' in content:
            schema_ref = content['application/json'].get('schema', {})
            if '$ref' in schema_ref:
                ref_name = schema_ref['$ref'].split('/')[-1]
                print(f"✅ Request Model: {ref_name}")
                if ref_name == "HoneypotRequest":
                    print(f"✅ CORRECT! Using HoneypotRequest model")
                else:
                    print(f"❌ WRONG MODEL: {ref_name}")
            else:
                print(f"❌ No schema reference found in requestBody")
        else:
            print(f"❌ No application/json content in requestBody")
    else:
        print(f"❌ Request Body is MISSING (This causes INVALID_REQUEST_BODY error)")

    # Check POST /honeypot RESPONSE schema
    post_response = post_op['responses']['200']
    print(f"\n📋 POST /honeypot RESPONSE Schema:")
    print(json.dumps(post_response, indent=2))
    
    # Check if it references HoneypotResponse
    if 'content' in post_response and 'application/json' in post_response['content']:
        schema_ref = post_response['content']['application/json'].get('schema', {})
        
        if '$ref' in schema_ref:
            ref_name = schema_ref['$ref'].split('/')[-1]
            print(f"\n✅ Response model: {ref_name}")
            
            if ref_name == "HoneypotResponse":
                print(f"✅ CORRECT! Using HoneypotResponse model")
                
                # Get the actual model definition
                if 'components' in schema and 'schemas' in schema['components']:
                    model_def = schema['components']['schemas'].get('HoneypotResponse', {})
                    print(f"\n📋 HoneypotResponse Schema:")
                    print(json.dumps(model_def, indent=2))
                    
                    # Verify it has status and reply properties
                    props = model_def.get('properties', {})
                    required = model_def.get('required', [])
                    
                    if 'status' in props and 'reply' in props:
                        print(f"\n✅ Schema has 'status' and 'reply' properties")
                        print(f"✅ Required fields: {required}")
                        print(f"\n🎉 OpenAPI schema is NOW CORRECT!")
                        print(f"\nThe GUVI tester should now be able to validate your API properly!")
                    else:
                        print(f"\n❌ Schema missing required properties")
            else:
                print(f"❌ WRONG MODEL: {ref_name}")
        else:
            print(f"\n❌ No schema reference found")
            print(f"Schema: {schema_ref}")
    else:
        print(f"\n❌ Response format incorrect")
    
except requests.exceptions.Timeout:
    print(f"\n⏰ Timeout - Render service might still be deploying...")
    print(f"   Wait a minute and try again: python verify_openapi_schema.py")
except Exception as e:
    print(f"\n❌ Error: {e}")

print("\n" + "=" * 80)

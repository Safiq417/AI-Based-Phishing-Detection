from google.genai import types
import inspect

print('GenerateContentConfigDict attributes:')
print([n for n in dir(types.GenerateContentConfigDict) if not n.startswith('_')])
print('\nannotations:')
print(getattr(types.GenerateContentConfigDict, '__annotations__', None))

print('\nTry common field names:')
for fld in ['instructions','system','system_instructions','system_prompt','prompt','instruction','system_message','system_messages']:
    try:
        cfg = types.GenerateContentConfigDict(**{fld:'hello'})
        print('Created with', fld, '->', cfg)
    except Exception as e:
        print('no', fld, '->', type(e).__name__, e)

# Try creating a full config with temperature and possible field
try:
    cfg = types.GenerateContentConfigDict(temperature=0.6, max_output_tokens=100)
    print('\nDefault create ok ->', cfg)
except Exception as e:
    print('\nDefault create error ->', type(e).__name__, e)

print('\nDone')

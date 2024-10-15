# Defining the function
def print_sample_invitation(mother, father, child, teacher, event):

    # Notice here the use of a multi-line format-string: f''' text here '''
    sample_text = f'''
Dear {mother} and {father}.
{teacher} and I would love to see you both as well as {child} at our {event} tomorrow evening.

Best regards,
Principal G. Sturgis.
'''
    # Print output
    print(sample_text)

# Call function
print_sample_invitation(mother='Karen', father='John', child='Noah', teacher='Tina', event='Pizza Party')

height = float(input('enter height in inches: '))
weight  = float(input('Enter weight in lbs: '))

def BMI(height, weight):
    bmi = weight / (height ** 2) * 783
    if (bmi < 16):
        return 'You are  severely underweight.', bmi
    
    elif (bmi >= 16 and bmi < 18.5):
        return 'You are underweight.', bmi
    
    elif (bmi >= 18.5 and bmi < 24.9):
        return 'You are normal weight.',bmi
    
    elif (bmi < 30):
        return 'You are overweight.', bmi
    
quote, bmi = BMI(height, weight)
print('your bmi is {} and you are {}'.format(bmi, quote))
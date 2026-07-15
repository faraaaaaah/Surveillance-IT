import pickle 
import pandas as pd 
with open(r'C:\Users\DELL\Desktop\stage\4eme\detection_anomalies\modele.pkl', 'rb') as f: 
    d = pickle.load(f) 
m = d['modele'] 
test = pd.DataFrame([[8, 47, 78, 0.1, 0.05, 0, 225, 0]], columns=d['features']) 
print('Score normal:', round(m.decision_function(test)[0], 4)) 
print('Predit:', m.predict(test)[0]) 
test2 = pd.DataFrame([[15, 46, 78, 15.8, 0.4, 0, 223, 0]], columns=d['features']) 
print('Score chrome:', round(m.decision_function(test2)[0], 4)) 
print('Predit:', m.predict(test2)[0]) 
test3 = pd.DataFrame([[95, 92, 78, 0.1, 0.05, 0, 225, 0]], columns=d['features']) 
print('Score vraie anomalie:', round(m.decision_function(test3)[0], 4)) 

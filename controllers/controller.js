import httpStatusText from'../utlits/httpStatus.js';
export async function postDiabetes(req, res) {
    let url = "http://web-production-59d8.up.railway.app/diabetes_prediction";
    const {Pregnancies, Glucose , BloodPressure
        , SkinThickness, Insulin, BMI
        , DiabetesPedigreeFunction, Age} = req.body;
    let options = {
    method: 'POST',
    headers: {
        Accept: '*/*',
        'Content-Type': 'application/json',
    },
        body: JSON.stringify(req.body)};

fetch(url, options)
    .then(res => res.json())
    .then(json => res.send({ status: httpStatusText.SUCCESS, data:{json}}))
    .catch(err => console.error('error:' + err));
    
    }
export async function postHeart(req, res) {
    

        let url = "http://web-production-6fc8.up.railway.app/heart_disease_prediction";
        const { Age, Sex, Cp 
            , Trestbps , Chol , Fbs 
            , Restecg , Thalach , Exang , Oldpeak , Slope , Ca , Thal} = req.body;
        let options = {
        method: 'POST',
        headers: {
            Accept: '*/*',
            'Content-Type': 'application/json',
        },
            body: JSON.stringify(req.body)};
    
    fetch(url, options)
        .then(res => res.json())
        .then(json => res.send({ status: httpStatusText.SUCCESS, data:{json}}))
        .catch(err => console.error('error:' + err));
        
        }
export async function postCancer(req, res) {
    

            let url = "https://web-production-b81f.up.railway.app/Breast_cancer_prediction";
            const {clump_thickness ,
                uniform_cell_size,
                uniform_cell_shape,
                marginal_adhesion,
                single_epithelial_size,
                bare_nuclei,
                bland_chromatin,
                normal_nucleoli,
                mitoses} = req.body;
            let options = {
            method: 'POST',
            headers: {
                Accept: '*/*',
                'Content-Type': 'application/json',
            },
                body: JSON.stringify(req.body)};
        
        fetch(url, options)
            .then(res => res.json())
            .then(json => res.send({ status: httpStatusText.SUCCESS, data:{json}}))
            .catch(err => console.error('error:' + err));
            
            }
export async function postParkinson(req, res) {
    

                let url = "https://web-production-fc13.up.railway.app/parkinson_prediction";
                const {
                    MDVP_fo_HZ
                    ,MDVP_Fhi_HZ
                    ,MDVP_Flo_HZ
                    ,MDVP_Jitter_percentage
                    ,MDVP_Jitter_Abs
                    ,MDVP_RAP
                    ,MDVP_PPQ
                    ,Jitter_DDP
                    ,MDVP_Shimmer
                    ,MDVP_Shimmer_dB
                    ,Shimmer_APQ3
                    ,Shimmer_APQ5
                    ,MDVP_APQ
                    ,Shimmer_DDA
                    ,NHR
                    ,HNR
                    ,RPDE
                    ,DFA
                    ,spread1
                    ,spread2,D2,PPE
                } = req.body;
                let options = {
                method: 'POST',
                headers: {
                    Accept: '*/*',
                    'Content-Type': 'application/json',
                },
                    body: JSON.stringify(req.body)};
            
            fetch(url, options)
                .then(res => res.json())
                .then(json => res.send({ status: httpStatusText.SUCCESS, data:{json}}))
                .catch(err => console.error('error:' + err));
                
                }
import React from 'react';

function AnimeCaptcha(props) {
    return (
        <div className="anime-captcha">
          <input type="hidden" name="anime-captcha-token" value={props.token}/>
          <div className="anime-captcha-title" dangerouslySetInnerHTML={{__html: props.title}}/>
          <div className="anime-captcha-grid">
            {props.questions.map((question) => {
                return <label key={question.field_name} className="anime-captcha-tile">
                         <input type="checkbox" className="anime-captcha-checkbox" name={question.field_name}
                                value="true" autoComplete="off"/>
                         <img className="anime-captcha-image" alt="" draggable="false" src={question.image}/>
                       </label>;
            })}
          </div>
        </div>
    );
}

export default AnimeCaptcha;

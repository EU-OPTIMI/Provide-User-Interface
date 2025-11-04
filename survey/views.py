from django.shortcuts import render
from django.http import JsonResponse
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from .models import SurveyResponse, Question, Answer
import json

@require_http_methods(["GET", "POST"])
def survey_view(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            
            # Create a new SurveyResponse object
            survey_response = SurveyResponse.objects.create(
                clarity=data.get('clarity'),
                ease_run=data.get('ease_run'),
                ease_provide=data.get('ease_provide'),
                issues=data.get('issues'),
                suggestions=data.get('suggestions')
            )

            # You can create answers for each question in the SurveyResponse if needed
            questions = Question.objects.all()
            for question in questions:
                answer_text = data.get(question.question_text)  # Assuming the answer keys match the question text
                if answer_text:
                    Answer.objects.create(
                        survey_response=survey_response,
                        question=question,
                        answer_text=answer_text
                    )

            messages.success(request, "Thank you for your feedback!")
            
            # Return JSON response to indicate success
            return JsonResponse({"status": "success", "message": "Thank you for your feedback!"})

        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)})

    else:
        return render(request, 'survey/survey.html')  # Render the survey template if GET request

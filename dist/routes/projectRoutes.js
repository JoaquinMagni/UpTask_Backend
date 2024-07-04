"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const express_validator_1 = require("express-validator");
const ProjectController_1 = require("../controllers/ProjectController");
const validation_1 = require("../middleware/validation");
const TaskController_1 = require("../controllers/TaskController");
const project_1 = require("../middleware/project");
const task_1 = require("../middleware/task");
const auth_1 = require("../middleware/auth");
const TeamController_1 = require("../controllers/TeamController");
const NoteController_1 = require("../controllers/NoteController");
const router = (0, express_1.Router)();
router.use(auth_1.authenticate);
router.post('/', (0, express_validator_1.body)('projectName')
    .notEmpty().withMessage('El nombre del proyecto es obligatorio.'), (0, express_validator_1.body)('clientName')
    .notEmpty().withMessage('El nombre del cliente es obligatorio.'), (0, express_validator_1.body)('description')
    .notEmpty().withMessage('La descripción del proyecto es obligatoria.'), validation_1.handleInputErrors, ProjectController_1.ProjectController.createProject);
router.get('/', ProjectController_1.ProjectController.getAllProjects);
router.get('/:id', (0, express_validator_1.param)('id').isMongoId().withMessage('ID no válido.'), validation_1.handleInputErrors, ProjectController_1.ProjectController.getProjectById);
/** Routes for tasks */
router.param('projectId', project_1.projectExist);
router.put('/:projectId', (0, express_validator_1.param)('projectId').isMongoId().withMessage('ID no válido.'), (0, express_validator_1.body)('projectName')
    .notEmpty().withMessage('El nombre del proyecto es obligatorio.'), (0, express_validator_1.body)('clientName')
    .notEmpty().withMessage('El nombre del cliente es obligatorio.'), (0, express_validator_1.body)('description')
    .notEmpty().withMessage('La descripción del proyecto es obligatoria.'), validation_1.handleInputErrors, task_1.hasAuthorization, ProjectController_1.ProjectController.updateProject);
router.delete('/:projectId', (0, express_validator_1.param)('projectId').isMongoId().withMessage('ID no válido.'), validation_1.handleInputErrors, task_1.hasAuthorization, ProjectController_1.ProjectController.deleteProject);
router.post('/:projectId/tasks', task_1.hasAuthorization, (0, express_validator_1.body)('name')
    .notEmpty().withMessage('El nombre de la tarea es obligatorio.'), (0, express_validator_1.body)('description')
    .notEmpty().withMessage('La descripción de la tarea es obligatoria.'), validation_1.handleInputErrors, TaskController_1.TaskController.createTask);
router.get('/:projectId/tasks', TaskController_1.TaskController.getProjectTasks);
router.param('taskId', task_1.taskExist);
router.param('taskId', task_1.taskBelongsToProject);
router.get('/:projectId/tasks/:taskId', (0, express_validator_1.param)('taskId').isMongoId().withMessage('ID no válido.'), validation_1.handleInputErrors, TaskController_1.TaskController.getTaskById);
router.put('/:projectId/tasks/:taskId', task_1.hasAuthorization, (0, express_validator_1.param)('taskId').isMongoId().withMessage('ID no válido.'), (0, express_validator_1.body)('name')
    .notEmpty().withMessage('El nombre de la tarea es obligatorio.'), (0, express_validator_1.body)('description')
    .notEmpty().withMessage('La descripción de la tarea es obligatoria.'), validation_1.handleInputErrors, TaskController_1.TaskController.updateTask);
router.delete('/:projectId/tasks/:taskId', task_1.hasAuthorization, (0, express_validator_1.param)('taskId').isMongoId().withMessage('ID no válido.'), validation_1.handleInputErrors, TaskController_1.TaskController.deleteTask);
router.post('/:projectId/tasks/:taskId/status', (0, express_validator_1.param)('taskId').isMongoId().withMessage('ID no válido.'), (0, express_validator_1.body)('status')
    .notEmpty().withMessage('El estado es obligatorio.'), validation_1.handleInputErrors, TaskController_1.TaskController.updateStatus);
/** Routes for teams */
router.post('/:projectId/team/find', (0, express_validator_1.body)('email')
    .isEmail().toLowerCase().withMessage('E-mail no válido.'), validation_1.handleInputErrors, TeamController_1.TeamMemberController.findMemberByEmail);
router.get('/:projectId/team', TeamController_1.TeamMemberController.getProjectMembers);
router.post('/:projectId/team', (0, express_validator_1.body)('id')
    .isMongoId().withMessage('ID no válido.'), validation_1.handleInputErrors, TeamController_1.TeamMemberController.addMemberById);
router.delete('/:projectId/team/:userId', (0, express_validator_1.param)('userId')
    .isMongoId().withMessage('ID no válido.'), validation_1.handleInputErrors, TeamController_1.TeamMemberController.removeMemberById);
/** Routes for Notes */
router.post('/:projectId/tasks/:taskId/notes', (0, express_validator_1.body)('content')
    .notEmpty().withMessage('El contenido de la nota es obligatorio.'), validation_1.handleInputErrors, NoteController_1.NoteController.createNote);
router.get('/:projectId/tasks/:taskId/notes', NoteController_1.NoteController.getTaskNotes);
router.delete('/:projectId/tasks/:taskId/notes/:noteId', (0, express_validator_1.param)('noteId').isMongoId().withMessage('ID no válido.'), validation_1.handleInputErrors, NoteController_1.NoteController.deleteNote);
exports.default = router;
//# sourceMappingURL=projectRoutes.js.map